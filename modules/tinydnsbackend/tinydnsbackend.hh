#ifndef TINYDNSBACKEND_HH
#define TINYDNSBACKEND_HH

#include <pdns/dnsbackend.hh>
#include <pdns/logger.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <cdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "cdb.hh"

class TinyDNSBackend : public DNSBackend
{
public:
	TinyDNSBackend(const string &suffix);
	void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
	bool list(const string &target, int domain_id);
	bool get(DNSResourceRecord &rr);
private:
	vector<string> getLocations();

	uint64_t d_taiepoch;
	int d_fd;
	QType d_qtype;
	CDB *d_cdbReader;
	DNSPacket *d_dnspacket;
	bool d_isWildcardQuery;
	bool d_isAxfr;
};

#endif // TINYDNSBACKEND_HH 
