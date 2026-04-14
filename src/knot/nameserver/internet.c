/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/libknot.h"
#include "libknot/rrtype/rdname.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/query_module.h"
#include "knot/server/server.h"
#include "knot/zone/serial.h"
#include "knot/zone/zonedb.h"
#include "contrib/mempattern.h"

/*! \brief Check if given node was already visited. */
static int wildcard_has_visited(knotd_qdata_t *qdata, const zone_node_t *node)
{
	struct wildcard_hit *item;
	WALK_LIST(item, qdata->extra->wildcards) {
		if (item->node == node) {
			return true;
		}
	}
	return false;
}

/*! \brief Mark given node as visited. */
static int wildcard_visit(knotd_qdata_t *qdata, const zone_node_t *node,
                          const zone_node_t *prev, const knot_dname_t *sname)
{
	assert(qdata);
	assert(node);

	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	knot_mm_t *mm = qdata->mm;
	struct wildcard_hit *item = mm_alloc(mm, sizeof(struct wildcard_hit));
	item->node = node;
	item->prev = prev;
	item->sname = sname;
	add_tail(&qdata->extra->wildcards, (node_t *)item);
	return KNOT_EOK;
}

/*! \brief Synthesizes a CNAME RR from a DNAME. */
static int dname_cname_synth(const knot_rrset_t *dname_rr,
                             const knot_dname_t *qname,
                             knot_rrset_t *cname_rrset,
                             knot_mm_t *mm)
{
	if (cname_rrset == NULL) {
		return KNOT_EINVAL;
	}
	knot_dname_t *owner_copy = knot_dname_copy(qname, mm);
	if (owner_copy == NULL) {
		return KNOT_ENOMEM;
	}
	knot_rrset_init(cname_rrset, owner_copy, KNOT_RRTYPE_CNAME, dname_rr->rclass,
	                dname_rr->ttl);

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = dname_rr->owner;
	const knot_dname_t *dname_tgt = knot_dname_target(dname_rr->rrs.rdata);
	size_t labels = knot_dname_labels(dname_wire, NULL);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt, mm);
	if (cname == NULL) {
		knot_dname_free(owner_copy, mm);
		return KNOT_ENOMEM;
	}

	/* Store DNAME into RDATA. */
	size_t cname_size = knot_dname_size(cname);
	uint8_t cname_rdata[cname_size];
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(cname, mm);

	int ret = knot_rrset_add_rdata(cname_rrset, cname_rdata, cname_size, mm);
	if (ret != KNOT_EOK) {
		knot_dname_free(owner_copy, mm);
		return ret;
	}

	return KNOT_EOK;
}

/*!
 * \brief Checks if the name created by replacing the owner of \a dname_rrset
 *        in the \a qname by the DNAME's target would be longer than allowed.
 */
static bool dname_cname_cannot_synth(const knot_rrset_t *rrset, const knot_dname_t *qname)
{
	if (knot_dname_labels(qname, NULL) - knot_dname_labels(rrset->owner, NULL) +
	    knot_dname_labels(knot_dname_target(rrset->rrs.rdata), NULL) > KNOT_DNAME_MAXLABELS) {
		return true;
	} else if (knot_dname_size(qname) - knot_dname_size(rrset->owner) +
	           knot_dname_size(knot_dname_target(rrset->rrs.rdata)) > KNOT_DNAME_MAXLEN) {
		return true;
	} else {
		return false;
	}
}

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(knotd_qdata_t *qdata)
{
	return knot_pkt_has_dnssec(qdata->query) &&
	       qdata->extra->contents->dnssec;
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer(knot_pkt_t *pkt, uint16_t type, knotd_qdata_t *qdata)
{
	/* Wildcard expansion or exact match, either way RRSet owner is
	 * is QNAME. We can fake name synthesis by setting compression hint to
	 * QNAME position. Just need to check if we're answering QNAME and not
	 * a CNAME target.
	 */
	uint16_t compr_hint = KNOT_COMPR_HINT_NONE;
	if (pkt->rrset_count == 0) { /* Guaranteed first answer. */
		compr_hint = KNOT_COMPR_HINT_QNAME;
	}

	unsigned put_rr_flags = (qdata->params->proto == KNOTD_QUERY_PROTO_UDP) ?
	                        KNOT_PF_NULL : KNOT_PF_NOTRUNC;
	put_rr_flags |= KNOT_PF_ORIGTTL;

	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);
	knot_rrset_t rrset;
	switch (type) {
	case KNOT_RRTYPE_ANY: /* Put one RRSet, not all. */
		rrset = node_rrset_at(qdata->extra->node, 0);
		break;
	case KNOT_RRTYPE_RRSIG: /* Put some RRSIGs, not all. */
		if (!knot_rrset_empty(&rrsigs)) {
			knot_rrset_init(&rrset, rrsigs.owner, rrsigs.type, rrsigs.rclass, rrsigs.ttl);
			int ret = knot_synth_rrsig(KNOT_RRTYPE_ANY, &rrsigs.rrs, &rrset.rrs, qdata->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			knot_rrset_init_empty(&rrset);
		}
		break;
	default: /* Single RRSet of given type. */
		rrset = node_rrset(qdata->extra->node, type);
		break;
	}

	if (knot_rrset_empty(&rrset)) {
		return KNOT_EOK;
	}

	return process_query_put_rr(pkt, qdata, &rrset, &rrsigs, compr_hint, put_rr_flags);
}

/*! \brief Puts optional SOA RRSet to the Authority section of the response. */
static int put_authority_soa(knot_pkt_t *pkt, knotd_qdata_t *qdata,
                             const zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &soa, &rrsigs,
	                            KNOT_COMPR_HINT_NONE,
	                            KNOT_PF_NOTRUNC | KNOT_PF_SOAMINTTL);
}

/*! \brief Put the delegation NS RRSet to the Authority section. */
static int put_delegation(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* Find closest delegation point. */
	while (!(qdata->extra->node->flags & NODE_FLAGS_DELEG)) {
		qdata->extra->node = node_parent(qdata->extra->node);
	}

	/* Insert NS record. */
	knot_rrset_t rrset = node_rrset(qdata->extra->node, KNOT_RRTYPE_NS);
	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
	                            KNOT_COMPR_HINT_NONE, 0);
}

static int put_nsec3_bitmap(const zone_node_t *for_node, knot_pkt_t *pkt,
                            knotd_qdata_t *qdata, uint32_t flags)
{
	const zone_node_t *node = node_nsec3_get(for_node);
	if (node == NULL) {
		return KNOT_EOK;
	}

	knot_rrset_t nsec3 = node_rrset(node, KNOT_RRTYPE_NSEC3);
	if (knot_rrset_empty(&nsec3)) {
		return KNOT_EOK;
	}

	knot_rrset_t rrsig = node_rrset(node, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &nsec3, &rrsig,
	                            KNOT_COMPR_HINT_NONE, flags);
}

/*! \brief Put additional records for given RR. */
static int put_additional(knot_pkt_t *pkt, const knot_rrset_t *rr,
                          knotd_qdata_t *qdata, knot_rrinfo_t *info, int state)
{
	if (rr->additional == NULL) {
		return KNOT_EOK;
	}

	/* Valid types for ADDITIONALS insertion. */
	/* \note Not resolving CNAMEs as MX/NS name must not be an alias. (RFC2181/10.3) */
	static uint16_t ar_type_list[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA, KNOT_RRTYPE_SVCB };
	static const int ar_type_count_default = 2;

	int ret = KNOT_EOK;

	additional_t *additional = (additional_t *)rr->additional;

	/* Iterate over the additionals. */
	for (uint16_t i = 0; i < additional->count; i++) {
		glue_t *glue = &additional->glues[i];
		uint32_t flags = KNOT_PF_NULL;

		/* Optional glue doesn't cause truncation. (RFC 1034/4.3.2 step 3b). */
		if (state != KNOTD_IN_STATE_DELEG || glue->optional) {
			flags |= KNOT_PF_NOTRUNC;
		}

		int ar_type_count = ar_type_count_default, ar_present = 0;
		if (rr->type == KNOT_RRTYPE_SVCB || rr->type == KNOT_RRTYPE_HTTPS) {
			ar_type_list[ar_type_count++] = rr->type;
		}

		uint16_t hint = knot_compr_hint(info, KNOT_COMPR_HINT_RDATA +
		                                glue->ns_pos);
		const zone_node_t *gluenode = glue_node(glue, qdata->extra->node);
		knot_rrset_t rrsigs = node_rrset(gluenode, KNOT_RRTYPE_RRSIG);
		for (int k = 0; k < ar_type_count; ++k) {
			knot_rrset_t rrset = node_rrset(gluenode, ar_type_list[k]);
			if (knot_rrset_empty(&rrset)) {
				continue;
			}
			ret = process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
			                           hint, flags);
			if (ret != KNOT_EOK) {
				break;
			}
			ar_present++;
		}

		if ((rr->type == KNOT_RRTYPE_SVCB || rr->type == KNOT_RRTYPE_HTTPS) &&
		    ar_present < ar_type_count && have_dnssec(qdata)) {
			// it would be nicer to have this in solve_additional_dnssec, but
			// it seems infeasible to transfer all the context there

			// adding an NSEC(3) record proving non-existence of some of the
			// glue with its bitmap
			if (knot_is_nsec3_enabled(qdata->extra->contents)) {
				ret = put_nsec3_bitmap(gluenode, pkt, qdata, flags);
			} else {
				knot_rrset_t nsec = node_rrset(gluenode, KNOT_RRTYPE_NSEC);
				if (!knot_rrset_empty(&nsec)) {
					ret = process_query_put_rr(pkt, qdata, &nsec, &rrsigs,
					                           KNOT_COMPR_HINT_NONE, flags);
				}
			}
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
}

static knotd_in_state_t follow_cname(knot_pkt_t *pkt, uint16_t rrtype, knotd_qdata_t *qdata)
{
	/* CNAME chain processing limit. */
	if (++qdata->extra->cname_chain > CNAME_CHAIN_MAX) {
		qdata->extra->node = NULL;
		return KNOTD_IN_STATE_HIT;
	}

	const zone_node_t *cname_node = qdata->extra->node;
	knot_rrset_t cname_rr = node_rrset(qdata->extra->node, rrtype);
	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);

	assert(!knot_rrset_empty(&cname_rr));

	/* Check whether RR is already in the packet. */
	uint16_t flags = KNOT_PF_CHECKDUP;

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	int ret = process_query_put_rr(pkt, qdata, &cname_rr, &rrsigs, 0, flags);
	switch (ret) {
	case KNOT_EOK:    break;
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	default:          return KNOTD_IN_STATE_ERROR;
	}

	/* Synthesize CNAME if followed DNAME. */
	if (rrtype == KNOT_RRTYPE_DNAME) {
		if (dname_cname_cannot_synth(&cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
		} else {
			knot_rrset_t dname_rr = cname_rr;
			ret = dname_cname_synth(&dname_rr, qdata->name,
			                        &cname_rr, &pkt->mm);
			if (ret != KNOT_EOK) {
				qdata->rcode = KNOT_RCODE_SERVFAIL;
				return KNOTD_IN_STATE_ERROR;
			}
			ret = process_query_put_rr(pkt, qdata, &cname_rr, NULL, 0, KNOT_PF_FREE);
			switch (ret) {
			case KNOT_EOK:    break;
			case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
			default:          return KNOTD_IN_STATE_ERROR;
			}
			if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_CNAME) {
				/* Synthesized CNAME is a perfect answer to query. */
				return KNOTD_IN_STATE_HIT;
			}
		}
	}

	/* Check if RR count increased. */
	if (pkt->rrset_count <= rr_count_before) {
		qdata->extra->node = NULL; /* Act as if the name leads to nowhere. */
		return KNOTD_IN_STATE_HIT;
	}

	/* If node is a wildcard, follow only if we didn't visit the same node
	 * earlier, as that would mean a CNAME loop. */
	if (knot_dname_is_wildcard(cname_node->owner)) {

		/* Check if is not in wildcard nodes (loop). */
		if (wildcard_has_visited(qdata, cname_node)) {
			qdata->extra->node = NULL; /* Act as if the name leads to nowhere. */

			if (wildcard_visit(qdata, cname_node, qdata->extra->previous, qdata->name) != KNOT_EOK) { // in case of loop, re-add this cname_node because it might have different qdata->name
				return KNOTD_IN_STATE_ERROR;
			}
			return KNOTD_IN_STATE_HIT;
		}

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, cname_node, qdata->extra->previous, qdata->name) != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* Now follow the next CNAME TARGET. */
	qdata->name = knot_cname_name(cname_rr.rrs.rdata);

	return KNOTD_IN_STATE_FOLLOW;
}

/*!
 * \brief Look up `target` in a locally-served zone and merge any records of
 * type `rtype` into `*synth`, updating synth->ttl to the running minimum.
 *
 * \return HIT if records were merged, NODATA if the target or type was not
 *         found, ERROR on allocation failure.
 */
static knotd_in_state_t follow_one_alias(server_t *server, const knot_dname_t *target,
                                         uint16_t rtype, knot_mm_t *mm, knot_rrset_t *synth)
{
	zone_t *tz = knot_zonedb_find_suffix(server->zone_db, target);
	if (tz == NULL || tz->contents == NULL) {
		return KNOTD_IN_STATE_NODATA;
	}
	const zone_node_t *tn = NULL, *cl = NULL, *pv = NULL;
	if (zone_contents_find_dname(tz->contents, target, &tn, &cl, &pv, false)
	    != ZONE_NAME_FOUND || tn == NULL) {
		return KNOTD_IN_STATE_NODATA;
	}
	knot_rrset_t src = node_rrset(tn, rtype);
	if (knot_rrset_empty(&src)) {
		return KNOTD_IN_STATE_NODATA;
	}
	synth->ttl = MIN(synth->ttl, src.ttl);
	if (knot_rdataset_merge(&synth->rrs, &src.rrs, mm) != KNOT_EOK) {
		return KNOTD_IN_STATE_ERROR;
	}
	return KNOTD_IN_STATE_HIT;
}

/*!
 * \brief Synthesises records from locally-served ALIAS target zones.
 *
 * When a zone node carries one or more ALIAS records, and the query is for any
 * type except ALIAS/RRSIG/NSEC, look up the queried type in every locally-served
 * ALIAS target and merge the results with any direct records of that type on the
 * alias node itself — ALIAS is additive, not replacing.
 *
 * Multiple ALIAS rdata are followed in turn; all results are merged into a
 * single rrset per type, analogous to how multiple A records combine.
 *
 * For qtype ANY, every non-skipped type that appears on the alias node or in
 * any locally-served target node is synthesised.
 *
 * TTL = min(alias_ttl, all contributing target TTLs, direct TTL).
 *
 * DNSSEC: synthesised records are not signed; this is a known limitation.
 */
static knotd_in_state_t follow_aliases(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);

	knot_rrset_t alias_rr = node_rrset(qdata->extra->node, KNOT_RRTYPE_ALIAS);
	assert(!knot_rrset_empty(&alias_rr));

	server_t *server = (server_t *)qdata->params->server;

	/* For ANY, collect the union of types across the alias node and all
	 * locally-served targets (skipping ALIAS/RRSIG/NSEC).  For a specific
	 * qtype, just use that single type. */
	uint16_t types[64];
	uint16_t ntypes = 0;

	if (qtype == KNOT_RRTYPE_ANY) {
		/* Types from the alias node's own rrsets. */
		for (uint16_t i = 0; i < qdata->extra->node->rrset_count; i++) {
			knot_rrset_t rs = node_rrset_at(qdata->extra->node, i);
			if (rs.type == KNOT_RRTYPE_ALIAS ||
			    rs.type == KNOT_RRTYPE_RRSIG ||
			    rs.type == KNOT_RRTYPE_NSEC) {
				continue;
			}
			bool dup = false;
			for (uint16_t j = 0; j < ntypes; j++) {
				if (types[j] == rs.type) { dup = true; break; }
			}
			if (!dup && ntypes < 64) {
				types[ntypes++] = rs.type;
			}
		}

		/* Types from each locally-served ALIAS target. */
		knot_rdata_t *rd = alias_rr.rrs.rdata;
		for (uint16_t i = 0; i < alias_rr.rrs.count;
		     i++, rd = knot_rdataset_next(rd)) {
			const knot_dname_t *tgt = knot_alias_name(rd);
			zone_t *tz = knot_zonedb_find_suffix(server->zone_db, tgt);
			if (tz == NULL || tz->contents == NULL) {
				continue;
			}
			const zone_node_t *tn = NULL, *cl = NULL, *pv = NULL;
			if (zone_contents_find_dname(tz->contents, tgt, &tn,
			                             &cl, &pv, false)
			    != ZONE_NAME_FOUND || tn == NULL) {
				continue;
			}
			for (uint16_t k = 0; k < tn->rrset_count; k++) {
				knot_rrset_t rs = node_rrset_at(tn, k);
				if (rs.type == KNOT_RRTYPE_ALIAS ||
				    rs.type == KNOT_RRTYPE_RRSIG ||
				    rs.type == KNOT_RRTYPE_NSEC) {
					continue;
				}
				bool dup = false;
				for (uint16_t j = 0; j < ntypes; j++) {
					if (types[j] == rs.type) { dup = true; break; }
				}
				if (!dup && ntypes < 64) {
					types[ntypes++] = rs.type;
				}
			}
		}
	} else {
		types[0] = qtype;
		ntypes = 1;
	}

	/* For each type, build one synthetic rrset = union of all target records
	 * of that type + direct records of that type on the alias node. */
	bool added = false;

	for (uint16_t ti = 0; ti < ntypes; ti++) {
		uint16_t rtype = types[ti];

		knot_dname_t *owner = knot_dname_copy(qdata->name, &pkt->mm);
		if (owner == NULL) {
			return KNOTD_IN_STATE_ERROR;
		}
		knot_rrset_t synth;
		knot_rrset_init(&synth, owner, rtype, KNOT_CLASS_IN, alias_rr.ttl);

		/* Merge records from each locally-served ALIAS target in turn. */
		knot_rdata_t *rdata = alias_rr.rrs.rdata;
		for (uint16_t j = 0; j < alias_rr.rrs.count;
		     j++, rdata = knot_rdataset_next(rdata)) {
			if (follow_one_alias(server, knot_alias_name(rdata),
			                     rtype, &pkt->mm, &synth)
			    == KNOTD_IN_STATE_ERROR) {
				return KNOTD_IN_STATE_ERROR;
			}
		}

		/* Also merge any direct records of this type on the alias node. */
		knot_rrset_t direct = node_rrset(qdata->extra->node, rtype);
		if (!knot_rrset_empty(&direct)) {
			synth.ttl = MIN(synth.ttl, direct.ttl);
			int ret = knot_rdataset_merge(&synth.rrs, &direct.rrs,
			                              &pkt->mm);
			if (ret != KNOT_EOK) {
				return KNOTD_IN_STATE_ERROR;
			}
		}

		if (knot_rrset_empty(&synth)) {
			continue;
		}

		int ret = process_query_put_rr(pkt, qdata, &synth, NULL,
		                               KNOT_COMPR_HINT_NONE, KNOT_PF_FREE);
		switch (ret) {
		case KNOT_EOK:    added = true; break;
		case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
		default:          return KNOTD_IN_STATE_ERROR;
		}
	}

	return added ? KNOTD_IN_STATE_HIT : KNOTD_IN_STATE_NODATA;
}

static knotd_in_state_t name_found(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);

	/* DS query at DP is answered normally, but everything else at/below DP
	 * triggers referral response. */
	if (((qdata->extra->node->flags & NODE_FLAGS_DELEG) && qtype != KNOT_RRTYPE_DS) ||
	    (qdata->extra->node->flags & NODE_FLAGS_NONAUTH)) {
		return KNOTD_IN_STATE_DELEG;
	}

	if (node_rrtype_exists(qdata->extra->node, KNOT_RRTYPE_CNAME)
	    && qtype != KNOT_RRTYPE_CNAME
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_NSEC
	    && qtype != KNOT_RRTYPE_ANY) {
		return follow_cname(pkt, KNOT_RRTYPE_CNAME, qdata);
	}

	/* ALIAS record — synthesise records from locally-served target zone.
	 * Fires for any qtype except ALIAS itself (returned as-is), RRSIG, and
	 * NSEC.  For A/AAAA/MX/TXT/SRV/etc the matching records are copied from
	 * the targets and merged with any direct records on this node.  For ANY
	 * every non-skipped type from the targets and this node is synthesised. */
	if (node_rrtype_exists(qdata->extra->node, KNOT_RRTYPE_ALIAS)
	    && qtype != KNOT_RRTYPE_ALIAS
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_NSEC) {
		return follow_aliases(pkt, qdata);
	}

	uint16_t old_rrcount = pkt->rrset_count;
	int ret = put_answer(pkt, qtype, qdata);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE && (qdata->params->proto == KNOTD_QUERY_PROTO_UDP)) {
			return KNOTD_IN_STATE_TRUNC;
		} else {
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* Check for NODATA (=0 RRs added). */
	if (old_rrcount == pkt->rrset_count) {
		return KNOTD_IN_STATE_NODATA;
	} else {
		return KNOTD_IN_STATE_HIT;
	}
}

static knotd_in_state_t name_not_found(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* Name is covered by wildcard. */
	if (qdata->extra->encloser->flags & NODE_FLAGS_WILDCARD_CHILD) {
		/* Find wildcard child in the zone. */
		const zone_node_t *wildcard_node =
			zone_contents_find_wildcard_child(
				qdata->extra->contents, qdata->extra->encloser);

		qdata->extra->node = wildcard_node;
		assert(qdata->extra->node != NULL);

		/* Follow expanded wildcard. */
		knotd_in_state_t next_state = name_found(pkt, qdata);

		/* Put to wildcard node list. */
		if (wildcard_has_visited(qdata, wildcard_node)) {
			return next_state;
		}
		if (wildcard_visit(qdata, wildcard_node, qdata->extra->previous, qdata->name) != KNOT_EOK) {
			next_state = KNOTD_IN_STATE_ERROR;
		}

		return next_state;
	}

	/* Name is under DNAME, use it for substitution. */
	bool encloser_auth = !(qdata->extra->encloser->flags & (NODE_FLAGS_NONAUTH | NODE_FLAGS_DELEG));
	knot_rrset_t dname_rrset = node_rrset(qdata->extra->encloser, KNOT_RRTYPE_DNAME);
	if (encloser_auth && !knot_rrset_empty(&dname_rrset)) {
		qdata->extra->node = qdata->extra->encloser; /* Follow encloser as new node. */
		return follow_cname(pkt, KNOT_RRTYPE_DNAME, qdata);
	}

	/* Look up an authoritative encloser or its parent. */
	const zone_node_t *node = qdata->extra->encloser;
	while (node->rrset_count == 0 || node->flags & NODE_FLAGS_NONAUTH) {
		node = node_parent(node);
		assert(node);
	}

	/* Name is below delegation. */
	if ((node->flags & NODE_FLAGS_DELEG)) {
		qdata->extra->node = node;
		return KNOTD_IN_STATE_DELEG;
	}

	return KNOTD_IN_STATE_MISS;
}

static knotd_in_state_t solve_name(knotd_in_state_t state, knot_pkt_t *pkt,
                                   knotd_qdata_t *qdata)
{
	int ret = zone_contents_find_dname(qdata->extra->contents, qdata->name,
	                                   &qdata->extra->node, &qdata->extra->encloser,
	                                   &qdata->extra->previous, qdata->query->flags & KNOT_PF_NULLBYTE);

	switch (ret) {
	case ZONE_NAME_FOUND:
		return name_found(pkt, qdata);
	case ZONE_NAME_NOT_FOUND:
		return name_not_found(pkt, qdata);
	case KNOT_EOUTOFZONE:
		assert(state == KNOTD_IN_STATE_FOLLOW); /* CNAME/DNAME chain only. */
		return KNOTD_IN_STATE_HIT;
	default:
		return KNOTD_IN_STATE_ERROR;
	}
}

static knotd_in_state_t solve_answer(knotd_in_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, void *ctx)
{
	int old_state = state;

	/* Do not solve if already solved, e.g. in a module. */
	if (state == KNOTD_IN_STATE_HIT) {
		return state;
	}

	/* Get answer to QNAME. */
	state = solve_name(state, pkt, qdata);

	/* Promote NODATA from a module if nothing found in zone. */
	if (state == KNOTD_IN_STATE_MISS && old_state == KNOTD_IN_STATE_NODATA) {
		state = old_state;
	}

	/* Is authoritative answer unless referral.
	 * Must check before we chase the CNAME chain. */
	if (state != KNOTD_IN_STATE_DELEG) {
		knot_wire_set_aa(pkt->wire);
	}

	/* Additional resolving for CNAME/DNAME chain. */
	while (state == KNOTD_IN_STATE_FOLLOW) {
		state = solve_name(state, pkt, qdata);
	}

	return state;
}

static knotd_in_state_t solve_answer_dnssec(knotd_in_state_t state, knot_pkt_t *pkt,
                                            knotd_qdata_t *qdata, void *ctx)
{
	/* RFC4035, section 3.1 RRSIGs for RRs in ANSWER are mandatory. */
	int ret = nsec_append_rrsigs(pkt, qdata, false);
	switch (ret) {
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	case KNOT_EOK:    return state;
	default:          return KNOTD_IN_STATE_ERROR;
	}
}

static knotd_in_state_t solve_authority(knotd_in_state_t state, knot_pkt_t *pkt,
                                        knotd_qdata_t *qdata, void *ctx)
{
	int ret = KNOT_ERROR;
	const zone_contents_t *zone_contents = qdata->extra->contents;

	switch (state) {
	case KNOTD_IN_STATE_HIT:    /* Positive response. */
		ret = KNOT_EOK;
		break;
	case KNOTD_IN_STATE_MISS:   /* MISS, set NXDOMAIN RCODE. */
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case KNOTD_IN_STATE_NODATA: /* NODATA append AUTHORITY SOA. */
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case KNOTD_IN_STATE_DELEG:  /* Referral response. */
		ret = put_delegation(pkt, qdata);
		break;
	case KNOTD_IN_STATE_TRUNC:  /* Truncated ANSWER. */
		ret = KNOT_ESPACE;
		break;
	case KNOTD_IN_STATE_ERROR:  /* Error resolving ANSWER. */
		break;
	default:
		assert(0);
		break;
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static knotd_in_state_t solve_authority_dnssec(knotd_in_state_t state, knot_pkt_t *pkt,
                                               knotd_qdata_t *qdata, void *ctx)
{
	int ret = KNOT_ERROR;

	/* Authenticated denial of existence. */
	switch (state) {
	case KNOTD_IN_STATE_HIT:    ret = KNOT_EOK; break;
	case KNOTD_IN_STATE_MISS:   ret = nsec_prove_nxdomain(pkt, qdata); break;
	case KNOTD_IN_STATE_NODATA: ret = nsec_prove_nodata(pkt, qdata); break;
	case KNOTD_IN_STATE_DELEG:  ret = nsec_prove_dp_security(pkt, qdata); break;
	case KNOTD_IN_STATE_TRUNC:  ret = KNOT_ESPACE; break;
	case KNOTD_IN_STATE_ERROR:  ret = KNOT_ERROR; break;
	default:
		assert(0);
		break;
	}

	/* RFC4035 3.1.3 Prove visited wildcards.
	 * Wildcard expansion applies for Name Error, Wildcard Answer and
	 * No Data proofs if at one point the search expanded a wildcard node. */
	if (ret == KNOT_EOK) {
		ret = nsec_prove_wildcards(pkt, qdata);
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in AUTHORITY are mandatory. */
	if (ret == KNOT_EOK) {
		ret = nsec_append_rrsigs(pkt, qdata, false);
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static knotd_in_state_t solve_additional(knotd_in_state_t state, knot_pkt_t *pkt,
                                         knotd_qdata_t *qdata, void *ctx)
{
	int ret = KNOT_EOK, rrset_count = pkt->rrset_count;

	/* Scan all RRs in ANSWER/AUTHORITY. */
	for (int i = 0; i < rrset_count; ++i) {
		knot_rrset_t *rr = &pkt->rr[i];
		knot_rrinfo_t *info = &pkt->rr_info[i];

		/* Skip types for which it doesn't apply. */
		if (!knot_rrtype_additional_needed(rr->type)) {
			continue;
		}

		/* Put additional records for given type. */
		ret = put_additional(pkt, rr, qdata, info, state);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static knotd_in_state_t solve_additional_dnssec(knotd_in_state_t state, knot_pkt_t *pkt,
                                                knotd_qdata_t *qdata, void *ctx)
{
	/* RFC4035, section 3.1 RRSIGs for RRs in ADDITIONAL are optional. */
	int ret = nsec_append_rrsigs(pkt, qdata, true);
	switch (ret) {
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	case KNOT_EOK:    return state;
	default:          return KNOTD_IN_STATE_ERROR;
	}
}

/*! \brief Helper for internet_query repetitive code. */
#define SOLVE_STEP(solver, state, context) \
	state = (solver)(state, pkt, qdata, context); \
	if (state == KNOTD_IN_STATE_TRUNC) { \
		return KNOT_STATE_DONE; \
	} else if (state == KNOTD_IN_STATE_ERROR) { \
		return KNOT_STATE_FAIL; \
	}

static knot_layer_state_t answer_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	knotd_in_state_t state = KNOTD_IN_STATE_BEGIN;
	struct query_plan *plan = qdata->extra->zone->query_plan;
	struct query_step *step;

	bool with_dnssec = have_dnssec(qdata);

	/* Resolve PREANSWER. */
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[KNOTD_STAGE_PREANSWER]) {
			assert(step->type == QUERY_HOOK_TYPE_IN);
			SOLVE_STEP(step->in_hook, state, step->ctx);
		}
	}

	/* Resolve ANSWER. */
	knot_pkt_begin(pkt, KNOT_ANSWER);
	SOLVE_STEP(solve_answer, state, NULL);
	if (with_dnssec) {
		SOLVE_STEP(solve_answer_dnssec, state, NULL);
	}
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[KNOTD_STAGE_ANSWER]) {
			assert(step->type == QUERY_HOOK_TYPE_IN);
			SOLVE_STEP(step->in_hook, state, step->ctx);
		}
	}

	/* Resolve AUTHORITY. */
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	SOLVE_STEP(solve_authority, state, NULL);
	if (with_dnssec) {
		SOLVE_STEP(solve_authority_dnssec, state, NULL);
	}
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[KNOTD_STAGE_AUTHORITY]) {
			assert(step->type == QUERY_HOOK_TYPE_IN);
			SOLVE_STEP(step->in_hook, state, step->ctx);
		}
	}

	/* Resolve ADDITIONAL. */
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	SOLVE_STEP(solve_additional, state, NULL);
	if (with_dnssec) {
		SOLVE_STEP(solve_additional_dnssec, state, NULL);
	}
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[KNOTD_STAGE_ADDITIONAL]) {
			assert(step->type == QUERY_HOOK_TYPE_IN);
			SOLVE_STEP(step->in_hook, state, step->ctx);
		}
	}

	/* Write resulting RCODE. */
	knot_wire_set_rcode(pkt->wire, qdata->rcode);

	return KNOT_STATE_DONE;
}

knot_layer_state_t internet_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check if valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_REFUSED);

	/* Check if a TSIG is present. */
	if (knot_pkt_has_tsig(qdata->query)) {
		NS_NEED_AUTH(qdata, ACL_ACTION_QUERY);

		/* Reserve space for TSIG. */
		int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
		if (ret != KNOT_EOK) {
			return KNOT_STATE_FAIL;
		}
	} else if (qdata->extra->zone->is_catalog_flag) {
		NS_NEED_AUTH(qdata, ACL_ACTION_QUERY);
	}

	/* Check if the zone is not empty or expired. */
	NS_NEED_ZONE_CONTENTS(qdata);

	/* Get answer to QNAME. */
	qdata->name = knot_pkt_qname(qdata->query);

	return answer_query(pkt, qdata);
}
