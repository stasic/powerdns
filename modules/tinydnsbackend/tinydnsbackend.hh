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
#include <pdns/lock.hh>


class TinyDNSBackend : public DNSBackend
{
public:
	// Methods for simple operation
	TinyDNSBackend(const string &suffix);
	void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
	bool list(const string &target, int domain_id);
	bool get(DNSResourceRecord &rr);
	void getAllDomains(vector<DomainInfo> *domains);

	//Master mode operation
	void getUpdatedMasters(vector<DomainInfo>* domains);
	void setNotified(uint32_t id, uint32_t serial);
private:
	vector<string> getLocations();

	//data member variables
	uint64_t d_taiepoch;
	QType d_qtype;
	CDB *d_cdbReader;
	DNSPacket *d_dnspacket; // used for location and edns-client support.
	bool d_isWildcardQuery; // Indicate if the query received was a wildcard query.
	bool d_isAxfr; // Indicate if we received a list() and not a lookup().
	

	// Statics
	static pthread_mutex_t s_domainInfoLock;
	static vector<DomainInfo> s_domainInfo;
};

#endif // TINYDNSBACKEND_HH 
