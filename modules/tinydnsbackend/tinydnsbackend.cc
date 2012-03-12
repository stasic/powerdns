#include "tinydnsbackend.hh"
#include "pdns/lock.hh"
#include <cdb.h>
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsrecords.hh>
#include <utility>
#include <boost/foreach.hpp>


static string backendname="[TinyDNSBackend]";
pthread_mutex_t TinyDNSBackend::s_domainInfoLock=PTHREAD_MUTEX_INITIALIZER;
vector<DomainInfo> TinyDNSBackend::s_domainInfo;


vector<string> TinyDNSBackend::getLocations()
{
	vector<string> ret;

	if (! d_dnspacket) {
		return ret;
	}

	//TODO: We do not have IPv6 support.
	if (d_dnspacket->getRealRemote().getBits() != 32) {
		return ret;
	}
	
	Netmask remote = d_dnspacket->getRealRemote();
	unsigned long addr = remote.getNetwork().sin4.sin_addr.s_addr;	

	char remoteAddr[4];
	remoteAddr[0] = (addr      )&0xff;
	remoteAddr[1] = (addr >>  8)&0xff;
	remoteAddr[2] = (addr >> 16)&0xff;
	remoteAddr[3] = (addr >> 24)&0xff;

	for (int i=4;i>=0;i--) {
		char *key = (char *)malloc(i+2);
		strncpy(key, remoteAddr, i);
		memmove(key+2, key, i);
		key[0]='\000';
		key[1]='\045';
		string searchkey(key, i+2);
		CDB *reader = new CDB(getArg("dbfile"));
		ret = reader->findall(searchkey);
		delete reader;
		free(key);

		//Biggest item wins, so when we find something, we can jump out.
		if (ret.size() > 0) {
			break;
		}
	}

	return ret; 
}

TinyDNSBackend::TinyDNSBackend(const string &suffix)
{
	setArgPrefix("tinydns"+suffix);
	d_taiepoch = 4611686018427387904ULL + getArgAsNum("tai-adjust");
}

void TinyDNSBackend::getUpdatedMasters(vector<DomainInfo>* domains) {
	Lock l(&s_domainInfoLock);
	
	if (s_domainInfo.size() == 0) {
		bool notifyOnStartup = mustDo("notify-on-startup");
		getAllDomains(&s_domainInfo);
		
		// little bit of optimization at startup.
		if (! notifyOnStartup) {
			return;	
		} else {
			for(vector<DomainInfo>::iterator di=s_domainInfo.begin(); di!=s_domainInfo.end(); ++di) {
				di->notified_serial = 0;
			}
		}
	}

	vector<DomainInfo> freshDomains; 
	getAllDomains(&freshDomains);

	bool found = false;
	BOOST_FOREACH(DomainInfo freshDi, freshDomains) {
		found = false;
		for(vector<DomainInfo>::iterator di=s_domainInfo.begin(); di!=s_domainInfo.end(); ++di) {
			if (di->zone.compare(freshDi.zone) == 0) {
				found=true;
				if (di->notified_serial != freshDi.serial) {
					DLOG(L<<Logger::Debug<<backendname<<"Adding "<<di->zone<<". New serial:"<<freshDi.serial<<";Notified_serial:"<<di->notified_serial<<endl);
					di->serial = freshDi.serial;
					domains->push_back(*di);
					break;
				}
			}
		}
		if (!found) {
			DLOG(L<<Logger::Info<<backendname<<"Found new domain while checking if we have updated serials: "<<freshDi.zone<<endl);
			s_domainInfo.push_back(freshDi);
			domains->push_back(freshDi);
		}
	}

	int remItem = 0;
	set<uint32_t> removeItems;
	for(vector<DomainInfo>::iterator di=s_domainInfo.begin(); di!=s_domainInfo.end(); ++di) {
		found = false;
		BOOST_FOREACH(DomainInfo freshDi, freshDomains) {
			if (di->zone.compare(freshDi.zone) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			removeItems.insert(remItem);
			DLOG(L<<Logger::Info<<backendname<<"Did not find zone "<<di->zone<<" while doing updated serials check. Removing!"<<endl);
		}
		remItem++;
	}
	BOOST_FOREACH(uint32_t rem, removeItems) {
		s_domainInfo.erase(s_domainInfo.begin() + rem);
	}
}

void TinyDNSBackend::setNotified(uint32_t id, uint32_t serial) {
	Lock l(&s_domainInfoLock);
	for(vector<DomainInfo>::iterator di=s_domainInfo.begin(); di!=s_domainInfo.end(); ++di) {
		if (di->id == id) {
			DLOG(L<<Logger::Debug<<backendname<<"Setting serial for "<<di->zone<<" to "<<serial<<endl);
			di->notified_serial = serial;
		}
	}
}

void TinyDNSBackend::getAllDomains(vector<DomainInfo> *domains) {
	d_isAxfr=true;

	d_cdbReader=new CDB(getArg("dbfile"));
	d_cdbReader->searchAll();
	DNSResourceRecord rr;

	int i = 1;
	while (get(rr)) {
		i++;
		if (rr.qtype.getCode() == QType::SOA) {
			SOAData sd;
			fillSOAData(rr.content, sd);

			DomainInfo di;
			di.id = i++;
			di.backend=this;
			di.zone = rr.qname;
			di.serial = sd.serial;
			di.notified_serial = sd.serial;
			di.kind = DomainInfo::Master;
			di.last_check = time(0);
			domains->push_back(di);
		}
	}
}

bool TinyDNSBackend::list(const string &target, int domain_id) {
	d_isAxfr=true;
	DNSLabel l(target.c_str());
	string key = l.binary();
	d_cdbReader=new CDB(getArg("dbfile"));
	return d_cdbReader->searchSuffix(key);
}

void TinyDNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId) {
	d_isAxfr = false;
	string queryDomain(qdomain.c_str(), qdomain.size());
	transform(queryDomain.begin(), queryDomain.end(), queryDomain.begin(), ::tolower);

	DNSLabel l(queryDomain.c_str());
	string key=l.binary();

	DLOG(L<<Logger::Debug<<backendname<<"[lookup] query for qtype ["<<qtype.getName()<<"] qdomain ["<<qdomain<<"]"<<endl);
//	DLOG(L<<Logger::Debug<<"[lookup] key ["<<makeHexDump(key)<<"]"<<endl);

	d_isWildcardQuery = false;
	if (key[0] == '\001' && key[1] == '\052') {
		d_isWildcardQuery = true;
		key.erase(0,2);
	}

	d_qtype=qtype;

	d_cdbReader=new CDB(getArg("dbfile"));
	d_cdbReader->searchKey(key);
	d_dnspacket = pkt_p;
}


bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	pair<string, string> record;

	while (d_cdbReader->readNext(record)) {
		string val = record.second; 
		string key = record.first;

		//DLOG(L<<Logger::Debug<<"[GET] Key: "<<makeHexDump(key)<<endl);
		//DLOG(L<<Logger::Debug<<"[GET] Val: "<<makeHexDump(val)<<endl);

		if (!d_isAxfr) {
			// If we have a wildcard query, but the record we got is not a wildcard, we skip.
			if (d_isWildcardQuery && val[2] != '\052' && val[2] != '\053') {
				continue;
			}

			// If it is NOT a wildcard query, but we do find a wildcard record, we skip it.	
			if (!d_isWildcardQuery && (val[2] == '\052' || val[2] == '\053')) {
				continue;
			}
		}
		

		QType valtype;
		vector<uint8_t> bytes;
		const char *sval = val.c_str();
		unsigned int len = val.size();
		bytes.resize(len);
		copy(sval, sval+len, bytes.begin());
		PacketReader pr(bytes);
		valtype = QType(pr.get16BitInt());
		//DLOG(L<<Logger::Debug<<"[GET] ValType:"<<valtype.getName()<<endl);
		//DLOG(L<<Logger::Debug<<"[GET] QType:"<<d_qtype.getName()<<endl);
		char locwild = pr.get8BitInt();

		if(locwild != '\075' && (locwild == '\076' || locwild == '\053')) 
		{
			char recloc[2];
			recloc[0] = pr.get8BitInt();
			recloc[1] = pr.get8BitInt();	
			
			bool foundLocation = false;
			// IF the dnspacket is not set, we simply do not output any queries with a location.
			vector<string> locations = getLocations();
			while(locations.size() > 0) {
				string locId = locations.back();
				locations.pop_back();

				if (recloc[0] == locId[0] && recloc[1] == locId[1]) {
					foundLocation = true;
					break;
				}
			}
			if (!foundLocation) {
				continue;
			} 
		}
		if(d_isAxfr || d_qtype.getCode() == QType::ANY || valtype == d_qtype) {
			// if we do an AXFR and we have a wildcard record, we need to add \001\052 before it.
			if (d_isAxfr && (val[2] == '\052' || val[2] == '\053' )) {
				key.insert(0, 1, '\052');
				key.insert(0, 1, '\001');
			}
			DNSLabel dnsKey(key.c_str(), key.size());
			rr.qname = dnsKey.human();
			// strip of the . (dot) at the end, if we don't packethandler does not handle this correctly.
			rr.qname = rr.qname.erase(rr.qname.size()-1, 1);
			rr.qtype = valtype;
			rr.ttl = pr.get32BitInt();
			
			rr.domain_id=-1;
			//TODO: 11:13.21 <@ahu> IT IS ALWAYS AUTH --- well not really because we are just a backend :-)
			// We could actually do NSEC3-NARROW DNSSEC according to Habbie, if we do, we need to change something ehre. 
			rr.auth = true;

			uint64_t timestamp = pr.get32BitInt();
			timestamp <<= 32;
			timestamp += pr.get32BitInt();
			if(timestamp) {
				uint64_t now = d_taiepoch + time(NULL);
				if (rr.ttl == 0) {
					if (timestamp < now) {
						continue;
					}
					rr.ttl = timestamp - now; 
				} else if (now <= timestamp) {
					continue;
				}
			}
	
			DNSRecord dr;
			dr.d_class = 1;
			dr.d_type = valtype.getCode();
			dr.d_clen = val.size()-pr.d_pos;
			DNSRecordContent *drc = DNSRecordContent::mastermake(dr, pr);

			string content = drc->getZoneRepresentation();
			delete drc;
			if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) {
				vector<string>parts;
				stringtok(parts,content," ");
				rr.priority=atoi(parts[0].c_str());
				rr.content=content.substr(parts[0].size()+1);
			} else {
				rr.content = content;
			}
			DLOG(L<<Logger::Debug<<backendname<<" Returning ["<<rr.content<<"] for ["<<rr.qname<<"] of RecordType ["<<rr.qtype.getName()<<"]"<<endl;);
			return true;
		}
	} // end of while
	DLOG(L<<Logger::Debug<<backendname<<"No more records to return."<<endl);
	
	delete d_cdbReader;
	return false;
}

// boilerplate
class TinyDNSFactory: public BackendFactory
{
public:
	TinyDNSFactory() : BackendFactory("tinydns") {}

	void declareArguments(const string &suffix="") {
		declare(suffix, "notify-on-startup", "Tell the TinyDNSBackend to nofity all the nameservers on startup. Default is yes.", "yes");
		declare(suffix, "dbfile", "Location of the cdb data file", "data.cdb");
		declare(suffix, "tai-adjust", "This adjusts the TAI value if timestamps are used. These seconds will be added to the start point (1970) and will allow you to adjust for leap seconds. The default is 10.", "10");
	}


	DNSBackend *make(const string &suffix="") {
		return new TinyDNSBackend(suffix);
	}
};

// boilerplate
class TinyDNSLoader
{
public:
	TinyDNSLoader() {
		BackendMakers().report(new TinyDNSFactory);
		L<<Logger::Info<<" [TinyDNSBackend] This is the TinyDNSBackend ("__DATE__", "__TIME__") reporting"<<endl;
	}
};

static TinyDNSLoader tinydnsloader;
