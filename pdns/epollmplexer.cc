#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"
#include <boost/lexical_cast.hpp>
#include "syncres.hh"
#include <sys/epoll.h>

using namespace boost;
using namespace std;

#include <sys/epoll.h>


class EpollFDMultiplexer : public FDMultiplexer
{
public:
  EpollFDMultiplexer();
  virtual ~EpollFDMultiplexer()
  {
    close(d_epollfd);
  }

  virtual int run(struct timeval* tv);

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, boost::any parameter);
  virtual void removeFD(callbackmap_t& cbmap, int fd);
  string getName()
  {
    return "epoll";
  }
private:
  int d_epollfd;
  boost::shared_array<epoll_event> d_eevents;
  static int s_maxevents; // not a hard maximum
};


static FDMultiplexer* make()
{
  return new EpollFDMultiplexer();
}

static struct RegisterOurselves
{
  RegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &make)); // priority 0!
  }
} doIt;


int EpollFDMultiplexer::s_maxevents=1024;
EpollFDMultiplexer::EpollFDMultiplexer() : d_eevents(new epoll_event[s_maxevents])
{
  d_epollfd=epoll_create(s_maxevents); // not hard max
  if(d_epollfd < 0)
    throw FDMultiplexerException("Setting up epoll: "+stringerror());
}

void EpollFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, boost::any parameter)
{
  Callback cb;
  cb.d_callback=toDo;
  cb.d_parameter=parameter;
  memset(&cb.d_ttd, 0, sizeof(cb.d_ttd));

  if(cbmap.count(fd))
    throw FDMultiplexerException("Tried to add fd "+lexical_cast<string>(fd)+ " to multiplexer twice");
  struct epoll_event eevent;
  
  eevent.events = (&cbmap == &d_readCallbacks) ? EPOLLIN : EPOLLOUT;
  
  eevent.data.u64=0; // placate valgrind (I love it so much)
  eevent.data.fd=fd; 

  if(epoll_ctl(d_epollfd, EPOLL_CTL_ADD, fd, &eevent) < 0)
    throw FDMultiplexerException("Adding fd to epoll set: "+stringerror());

  cbmap[fd]=cb;
}

void EpollFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+lexical_cast<string>(fd)+ " from multiplexer");

  if(epoll_ctl(d_epollfd, EPOLL_CTL_DEL, fd, 0) < 0)
    throw FDMultiplexerException("Removing fd from epoll set: "+stringerror());
}

int EpollFDMultiplexer::run(struct timeval* now)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  
  int ret=epoll_wait(d_epollfd, d_eevents.get(), s_maxevents, 500);
  gettimeofday(now,0);
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("select returned error: "+stringerror());

  if(ret==0) // nothing
    return 0;

  d_inrun=true;

  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(d_eevents[n].data.fd);
    
    if(d_iter != d_readCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
    }

    d_iter=d_writeCallbacks.find(d_eevents[n].data.fd);
    
    if(d_iter != d_writeCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
    }
  }

  d_inrun=false;
  return 0;
}

#if 0
void acceptData(int fd, boost::any& parameter)
{
  cout<<"Have data on fd "<<fd<<endl;
  Socket* sock=boost::any_cast<Socket*>(parameter);
  string packet;
  IPEndpoint rem;
  sock->recvFrom(packet, rem);
  cout<<"Received "<<packet.size()<<" bytes!\n";
}


int main()
{
  Socket s(InterNetwork, Datagram);
  
  IPEndpoint loc("0.0.0.0", 2000);
  s.bind(loc);

  EpollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif

