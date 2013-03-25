#ifndef PROXY_HPP_MODULE
#define PROXY_HPP_MODULE

#include <fastcgi2/component_factory.h>
#include <fastcgi2/handler.h>
#include <fastcgi2/request.h>
#include <fastcgi2/logger.h>

#include <boost/tokenizer.hpp>
#include <boost/shared_ptr.hpp>

#include <elliptics/proxy.hpp>

#include <map>
#include <set>

#include "component_base.hpp"
#include "embed_processor.hpp"

class Proxy :
	virtual public ComponentBase
	, virtual public fastcgi::Handler
{
private:
	typedef void (Proxy::*RequestHandler) (fastcgi::Request *request);
	//using RequestHandler = void (Proxy::*) (fastcgi::Request *request);
	typedef std::map <std::string, RequestHandler> RequestHandlers;	

public:
	typedef boost::char_separator <char> Separator;
	typedef boost::tokenizer <Separator> Tokenizer;

	struct Signature {
		std::string path;
		std::string key;
	};

	Proxy (fastcgi::ComponentContext *context);
	virtual ~Proxy ();

	virtual void onLoad ();
	virtual void onUnload ();
	virtual void handleRequest (fastcgi::Request *request, fastcgi::HandlerContext *context);

private:
	void registerHandler (const char *name, RequestHandler handler);

	void uploadHandler (fastcgi::Request *request);
	void getHandler (fastcgi::Request *request);
	void deleteHandler (fastcgi::Request *request);
	void downloadInfoHandler (fastcgi::Request *request);
	void bulkUploadHandler (fastcgi::Request *request);
	void bulkGetHandler (fastcgi::Request *request);
	void pingHandler (fastcgi::Request *request);
	void statLogHandler (fastcgi::Request *request);

	void allowOrigin (fastcgi::Request *request) const;

	boost::shared_ptr <elliptics::EllipticsProxy> ellipticsProxy_;

	RequestHandlers handlers_;

	int write_port_;

	std::set <std::string> deny_list_;
	std::set <std::string> allow_list_;
	std::map <std::string, std::string> typemap_;
	std::map <uint32_t, EmbedProcessorModuleBase *> embed_processors_;
	std::set <std::string> allow_origin_domains_;
	std::set <std::string> allow_origin_handlers_;
};

#endif /* PROXY_HPP_MODULE */
