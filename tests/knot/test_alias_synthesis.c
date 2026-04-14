/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Unit tests for ALIAS record A/AAAA synthesis in name_found().
 *
 * Scenarios tested:
 *  1. A query  → synthesised A record from locally-served target zone
 *  2. AAAA query → synthesised AAAA record
 *  3. ANY query  → synthesised A + AAAA
 *  4. ALIAS qtype → ALIAS record returned as-is (no synthesis)
 *  5. MX query with ALIAS present → NODATA (synthesis only for A/AAAA/ANY)
 *  6. A query, ALIAS target not in any local zone → NODATA
 *  7. TTL capping: synthesised TTL = min(alias_ttl, target_ttl)
 */

#include <string.h>
#include <stdlib.h>

#include <tap/basic.h>
#include <tap/files.h>

#include "libknot/descriptor.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_query.h"
#include "knot/zone/zone.h"
#include "knot/zone/contents.h"
#include "knot/zone/adjust.h"
#include "knot/zone/zonedb.h"
#include "libzscanner/scanner.h"
#include "test_server.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"

/* ------------------------------------------------------------------ helpers */

/* zs_scanner callback: add each scanned RR to a zone_contents_t. */
static void scan_add_rr(zs_scanner_t *sc)
{
	zone_contents_t *cont = sc->process.data;
	knot_dname_t *owner = knot_dname_copy(sc->r_owner, NULL);
	assert(owner != NULL);
	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, sc->r_type, sc->r_class, sc->r_ttl);
	(void)knot_rrset_add_rdata(&rr, sc->r_data, sc->r_data_length, NULL);
	zone_node_t *node = NULL;
	(void)zone_contents_add_rr(cont, &rr, &node);
	knot_rrset_clear(&rr, NULL);
}

/*!
 * Parse a zone from text, create a zone_t, and insert it into the server's
 * zone_db.  The first token of zone_text must be the zone origin (FQDN with
 * trailing dot).  Returns the zone pointer (owned by server->zone_db).
 */
static zone_t *add_text_zone(server_t *server, const char *zone_text)
{
	char origin_str[256];
	sscanf(zone_text, "%255s", origin_str);

	knot_dname_t *origin = knot_dname_from_str_alloc(origin_str);
	assert(origin != NULL);

	zone_t *zone = zone_new(origin);
	assert(zone != NULL);
	knot_dname_free(origin, NULL);

	zone->server = server;
	zone->contents = zone_contents_new(zone->name, true);
	assert(zone->contents != NULL);

	zs_scanner_t sc;
	int ok_scan =
		zs_init(&sc, origin_str, KNOT_CLASS_IN, 300) == 0 &&
		zs_set_input_string(&sc, zone_text, strlen(zone_text)) == 0 &&
		zs_set_processing(&sc, scan_add_rr, NULL, zone->contents) == 0 &&
		zs_parse_all(&sc) == 0 &&
		sc.error.code == ZS_OK;
	ok(ok_scan, "zone parsed: %s", origin_str);
	zs_deinit(&sc);

	(void)zone_adjust_full(zone->contents, 1);
	knot_zonedb_insert(server->zone_db, zone);
	return zone;
}

/*!
 * Build a query packet for <owner>/<qclass>/<qtype>, run it through the
 * process_query layer, and return the answer packet.  The layer is reset
 * so the next call starts fresh.  Caller must knot_pkt_free() the result.
 */
static knot_pkt_t *exec_query(knot_layer_t *layer, knot_pkt_t *query,
                               const knot_dname_t *owner, uint16_t qtype)
{
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	assert(answer != NULL);

	knot_layer_reset(layer);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, owner, KNOT_CLASS_IN, qtype);
	knot_pkt_parse(query, 0);
	knot_layer_consume(layer, query);
	knot_layer_produce(layer, answer);
	return answer;
}

/* Return number of RRsets in the ANSWER section of pkt. */
static uint16_t answer_count(const knot_pkt_t *pkt)
{
	return knot_pkt_section(pkt, KNOT_ANSWER)->count;
}

/* Return the i-th RRset in the ANSWER section, or NULL. */
static const knot_rrset_t *answer_rr(const knot_pkt_t *pkt, uint16_t i)
{
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	if (i >= an->count) {
		return NULL;
	}
	return knot_pkt_rr(an, i);
}

/* ------------------------------------------------------------------- main */

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	char *temp_dir = test_mkdtemp();
	ok(temp_dir != NULL, "make temporary directory");

	server_t server;
	int ret = create_fake_server(&server, &mm, temp_dir);
	is_int(KNOT_EOK, ret, "alias: fake server init");
	if (ret != KNOT_EOK) {
		goto fatal;
	}

	/* Target zone: _ips.example.
	 *   web._ips.example.  300  A    192.0.2.1
	 *   web._ips.example.  300  AAAA 2001:db8::1          */
	add_text_zone(&server,
		"_ips.example. 300 IN SOA ns. mail. 1 3600 900 604800 300\n"
		"_ips.example. 300 IN NS  ns.\n"
		"web._ips.example. 300 IN A    192.0.2.1\n"
		"web._ips.example. 300 IN AAAA 2001:db8::1\n");

	/* Alias zone: example.
	 *   www.example.  600  ALIAS  web._ips.example.
	 *   www.example.  300  MX     10 mail.example.  (coexists with ALIAS) */
	add_text_zone(&server,
		"example. 300 IN SOA ns. mail. 1 3600 900 604800 300\n"
		"example. 300 IN NS  ns.\n"
		"www.example. 600 IN ALIAS web._ips.example.\n"
		"www.example. 300 IN MX    10 mail.example.\n");

	/* Non-local alias zone: other.example.
	 *   www.other.example.  300  ALIAS  web.external.tld.  */
	add_text_zone(&server,
		"other.example. 300 IN SOA ns. mail. 1 3600 900 604800 300\n"
		"other.example. 300 IN NS  ns.\n"
		"www.other.example. 300 IN ALIAS web.external.tld.\n");

	/* Set up query-processing layer. */
	knot_layer_t proc;
	memset(&proc, 0, sizeof(proc));
	knot_layer_init(&proc, &mm, process_query_layer());

	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	sockaddr_set(&ss, AF_INET, "127.0.0.1", 53);
	knotd_qdata_params_t params = {
		.proto  = KNOTD_QUERY_PROTO_TCP,
		.remote = &ss,
		.server = &server,
	};
	knot_layer_begin(&proc, &params);

	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, proc.mm);
	assert(query != NULL);

	/* Wire-format dnames used as query names. */
	const knot_dname_t *www_example =
		(const knot_dname_t *)"\x03""www""\x07""example""\x00";
	const knot_dname_t *www_other =
		(const knot_dname_t *)"\x03""www""\x05""other""\x07""example""\x00";

	/* ---------------------------------------------------------------- */
	/* Test 1: A query → synthesised A record                           */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_A);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias A: NOERROR");
		is_int(1, answer_count(ans), "alias A: 1 RRset in answer");
		const knot_rrset_t *rr = answer_rr(ans, 0);
		if (rr != NULL) {
			is_int(KNOT_RRTYPE_A, rr->type,
			       "alias A: answer type is A");
			is_int(1, rr->rrs.count, "alias A: 1 rdata");
			ok(rr->rrs.rdata != NULL &&
			   rr->rrs.rdata->len == 4 &&
			   memcmp(rr->rrs.rdata->data, "\xc0\x00\x02\x01", 4) == 0,
			   "alias A: rdata is 192.0.2.1");
		} else {
			skip_block(3, "alias A: no answer RRset");
		}
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 2: AAAA query → synthesised AAAA record                     */
	/* ---------------------------------------------------------------- */
	{
		/* 2001:db8::1 in network byte order */
		static const uint8_t ipv6_addr[16] = {
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		};
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_AAAA);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias AAAA: NOERROR");
		is_int(1, answer_count(ans), "alias AAAA: 1 RRset in answer");
		const knot_rrset_t *rr = answer_rr(ans, 0);
		if (rr != NULL) {
			is_int(KNOT_RRTYPE_AAAA, rr->type,
			       "alias AAAA: answer type is AAAA");
			ok(rr->rrs.rdata != NULL &&
			   rr->rrs.rdata->len == 16 &&
			   memcmp(rr->rrs.rdata->data, ipv6_addr, 16) == 0,
			   "alias AAAA: rdata is 2001:db8::1");
		} else {
			skip_block(2, "alias AAAA: no answer RRset");
		}
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 3: ANY query → both A and AAAA synthesised                  */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_ANY);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias ANY: NOERROR");
		bool has_a = false, has_aaaa = false;
		for (uint16_t i = 0; i < answer_count(ans); i++) {
			const knot_rrset_t *rr = answer_rr(ans, i);
			if (rr->type == KNOT_RRTYPE_A)    has_a    = true;
			if (rr->type == KNOT_RRTYPE_AAAA) has_aaaa = true;
		}
		ok(has_a,    "alias ANY: A record synthesised");
		ok(has_aaaa, "alias ANY: AAAA record synthesised");
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 4: ALIAS qtype → ALIAS record returned as-is               */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_ALIAS);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias ALIAS-qtype: NOERROR");
		is_int(1, answer_count(ans),
		       "alias ALIAS-qtype: 1 RRset in answer");
		const knot_rrset_t *rr = answer_rr(ans, 0);
		if (rr != NULL) {
			is_int(KNOT_RRTYPE_ALIAS, rr->type,
			       "alias ALIAS-qtype: answer type is ALIAS");
		} else {
			skip("alias ALIAS-qtype: no answer RRset");
		}
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 5: MX query with ALIAS present → real MX returned, not      */
	/* suppressed by ALIAS and not synthesised from target zone.         */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_MX);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias MX: NOERROR");
		is_int(1, answer_count(ans),
		       "alias MX: 1 RRset in answer (real MX, not synthesised)");
		const knot_rrset_t *rr = answer_rr(ans, 0);
		if (rr != NULL) {
			is_int(KNOT_RRTYPE_MX, rr->type,
			       "alias MX: answer type is MX (not synthesised A/AAAA)");
		} else {
			skip("alias MX: no answer RRset to check type");
		}
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 6: ALIAS target not served locally → NODATA                 */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_other, KNOT_RRTYPE_A);
		is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(ans->wire),
		       "alias non-local A: NOERROR");
		is_int(0, answer_count(ans),
		       "alias non-local A: 0 records (target not local)");
		knot_pkt_free(ans);
	}

	/* ---------------------------------------------------------------- */
	/* Test 7: synthesised TTL = min(alias_ttl=600, target_ttl=300)     */
	/* ---------------------------------------------------------------- */
	{
		knot_pkt_t *ans = exec_query(&proc, query, www_example, KNOT_RRTYPE_A);
		const knot_rrset_t *rr = answer_rr(ans, 0);
		if (rr != NULL) {
			ok(rr->ttl <= 300,
			   "alias TTL: synthesised TTL (%u) <= target TTL (300)",
			   rr->ttl);
		} else {
			skip("alias TTL: no answer RRset to check TTL");
		}
		knot_pkt_free(ans);
	}

	knot_layer_finish(&proc);

fatal:
	mp_delete((struct mempool *)mm.ctx);
	server_deinit(&server);
	conf_free(conf());
	test_rm_rf(temp_dir);
	free(temp_dir);
	return 0;
}
