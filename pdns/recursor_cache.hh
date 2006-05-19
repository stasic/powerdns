#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include "misc.hh"
#include <iostream>
#include <boost/utility.hpp>
#undef L
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>
#if BOOST_VERSION >= 103300
#include <boost/multi_index/hashed_index.hpp>
#endif

#undef max

#define L theL()
using namespace boost;
using namespace ::boost::multi_index;

class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  MemRecursorCache() : d_followRFC2181(false), d_cachecachevalid(false)
  {}
  unsigned int size();
  unsigned int bytes();
  int get(time_t, const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  void replace(time_t, const string &qname, const QType& qt,  const set<DNSResourceRecord>& content, bool auth);
  void doPrune(void);
  void doSlash(int perc);
  void doDumpAndClose(int fd);
  int doWipeCache(const string& name);
  uint64_t cacheHits, cacheMisses;
  bool d_followRFC2181;

private:
  struct StoredRecord
  {
    mutable uint32_t d_ttd;

    string d_string;

    bool operator<(const StoredRecord& rhs) const
    {
      return d_string < rhs.d_string;
    }

    unsigned int size() const
    {
      return ( unsigned int ) 4+d_string.size();
    }

  };

  struct predicate
  {
    predicate(uint32_t limit) : d_limit(limit)
    {
    }
    
    bool operator()(const StoredRecord& sr) const
    {
      return sr.d_ttd <= d_limit;
    }
    uint32_t d_limit;
  };

  //   typedef __gnu_cxx::hash_map<string, vector<StoredRecord> > cache_t;
  struct CacheEntry
  {
    string d_qname;
    uint16_t d_qtype;

    CacheEntry(const tuple<string, uint16_t>& key, const vector<StoredRecord>& records) : 
      d_qname(key.get<0>()), d_qtype(key.get<1>()), d_records(records)
    {}

    typedef vector<StoredRecord> records_t;
    records_t d_records;
    uint32_t getTTD() const
    {
      if(d_records.size()==1)
	return d_records.begin()->d_ttd;

      uint32_t earliest=numeric_limits<uint32_t>::max();
      for(records_t::const_iterator i=d_records.begin(); i != d_records.end(); ++i)
	earliest=min(earliest, i->d_ttd);
      return earliest;
    }

  };

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,string,&CacheEntry::d_qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::d_qtype>
                      >,
                      composite_key_compare<CIStringCompare, std::less<uint16_t> >
                >,
               sequenced<>
               >
  > cache_t;

  cache_t d_cache;
  pair<cache_t::iterator, cache_t::iterator> d_cachecache;
  string d_cachedqname;
  bool d_cachecachevalid;
};
string DNSRR2String(const DNSResourceRecord& rr);
DNSResourceRecord String2DNSRR(const string& qname, const QType& qt, const string& serial, uint32_t ttd);

#endif
