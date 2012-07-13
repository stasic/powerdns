#include "resolver.hh"
#include "statbag.hh"
#include "arguments.hh"

StatBag S;

ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

int main(int argc, char **argv)
try
{
	AXFRRetriever r(0);
    Resolver::res_t recs;
    reportAllTypes();

    while(r.getChunk(recs, true)) {
		for(Resolver::res_t::iterator i=recs.begin();i!=recs.end();++i) {
			cout<<(i->qname)<<".\t";
			cout<<(i->ttl)<<"\t";
			cout<<"IN"<<"\t";
			cout<<(i->qtype.getName())<<"\t";
			cout<<(i->content)<<endl;
		}
	}
}
catch (std::exception &e)
{
	cerr<<"Fatal: "<<e.what()<<endl;
}
catch (ResolverException &e)
{
	cerr<<"Fatal: "<<e.reason<<endl;
}