#include "proxy.hpp"

#include <fastcgi2/except.h>
#include <fastcgi2/config.h>

#include <cstring>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <string>
#include <chrono>

#include <boost/lexical_cast.hpp>
#include <boost/optional/optional.hpp>

#include <openssl/md5.h>

static size_t paramsNum (Proxy::Tokenizer &tok) {
	size_t result = 0;
	for (auto it = ++tok.begin (), end = tok.end (); end != it; ++it) {
		++result;
	}
	return result;
}

static void dnet_parse_numeric_id (const std::string &value, struct dnet_id &id) {
	unsigned char ch[5];
	unsigned int i, len = value.size ();
	const char *ptr = value.data();

	memset(id.id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = ptr[2*i + 0];
		ch[3] = ptr[2*i + 1];

		id.id[i] = (unsigned char)strtol ((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = ptr[2*i + 0];
		ch[3] = '0';

		id.id[i] = (unsigned char)strtol ((const char *)ch, NULL, 16);
	}
}

static void getGroups (fastcgi::Request *request, std::vector <int> &groups, int count = 0) {
	if (request->hasArg ("groups")) {
		Proxy::Separator sep (":");
		Proxy::Tokenizer tok (request->getArg ("groups"), sep);

		try {
			for (auto it = tok.begin (), end = tok.end (); end != it; ++it) {
				groups.push_back (boost::lexical_cast <int> (*it));
			}
		}
		catch (...) {
			//log ()->debug ("Exception: groups <%s> is incorrect",
			  //			 request->getArg ("groups").c_str ());
			//throw fastcgi::HttpException (503);
			std::stringstream ss;
			ss << "groups <" << request->getArg ("groups") << "> is incorrect";
			std::string str = ss.str ();
			throw std::runtime_error (str);
		}
	}

	if (count != 0 && (size_t)count < groups.size ()) {
		groups.erase(groups.begin () + count, groups.end ());
	}
}

static std::string getFilename (fastcgi::Request *request) {
	if (request->hasArg ("name")) {
		return request->getArg ("name");
	} else {
		std::string scriptname = request->getScriptName ();
		std::string::size_type begin = scriptname.find ('/', 1) + 1;
		std::string::size_type end = scriptname.find ('?', begin);
		return scriptname.substr (begin, end - begin);
	}
}

static elliptics::Key getKey (fastcgi::Request *request) {
	if (request->hasArg ("id")) {
		struct dnet_id id;
		dnet_parse_numeric_id (request->getArg ("id"), id);
		elliptics::ID ID (id);
		return elliptics::Key (ID);
	} else {
		std::string filename = getFilename (request);
		int column = request->hasArg ("column") ? boost::lexical_cast <int> (request->getArg ("column")) : 0;
		return elliptics::Key (filename, column);
	}
}

namespace detail {

template <size_t size>
struct BSwap {};

template <>
struct BSwap <2> {
	template <typename T>
	static void process (T &ob) {
		ob = dnet_bswap16 (ob);
	}
};

template <>
struct BSwap <4> {
	template <typename T>
	static void process (T &ob) {
		ob = dnet_bswap32 (ob);
	}
};

template <>
struct BSwap <8> {
	template <typename T>
	static void process (T &ob) {
		ob = dnet_bswap64 (ob);
	}
};

} // namespace detail


struct BSwap {
	template <typename T>
	static void process (T &ob) {
		detail::BSwap <sizeof (T)>::process (ob);
	}
};

template <typename T>
static void bwriteToSS (std::ostringstream &oss, T ob) {
	BSwap::process (ob);
	oss.write ((const char *)&ob, sizeof (T));
}

template <typename T>
static void breadFromSS (std::istringstream &iss, T &ob) {
	iss.read ((char *)&ob, sizeof (T));
	BSwap::process (ob);
}

Proxy::Proxy (fastcgi::ComponentContext *context)
	: ComponentBase (context)
{}

Proxy::~Proxy () {
}

void Proxy::onLoad () {
	ComponentBase::onLoad ();
	const fastcgi::Config *config = context ()->getConfig ();
	std::string path(context()->getComponentXPath());

	elliptics::EllipticsProxy::config elconf;
	std::vector<std::string> names;

	elconf.state_num = config->asInt(path + "/dnet/die-limit");
	elconf.base_port = config->asInt(path + "/dnet/base-port");
	write_port_ = config->asInt(path + "/dnet/write-port", 9000);
	elconf.directory_bit_num = config->asInt(path + "/dnet/directory-bit-num");
	elconf.eblob_style_path = config->asInt(path + "/dnet/eblob_style_path", 0);

	elconf.replication_count = config->asInt(path + "/dnet/replication-count", 0);
	elconf.chunk_size = config->asInt(path + "/dnet/chunk_size", 0);
	if (elconf.chunk_size < 0) elconf.chunk_size = 0;


	elconf.log_path = config->asString(path + "/dnet/log/path");
	elconf.log_mask = config->asInt(path + "/dnet/log/mask");

	elconf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
	elconf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
	elconf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

	names.clear();
	config->subKeys(path + "/dnet/remote/addr", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end();
		 end != it; ++it) {
		std::string remote = config->asString(it->c_str());
		Separator sep(":");
		Tokenizer tok(remote, sep);

		if (paramsNum(tok) != 2) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		std::string addr;
		int port, family;

		try {
			Tokenizer::iterator tit = tok.begin();
			addr = *tit;
			port = boost::lexical_cast<int>(*(++tit));
			family = boost::lexical_cast<int>(*(++tit));
			elconf.remotes.push_back(
						elliptics::EllipticsProxy::remote(
							addr, port, family));
			log ()->info("added dnet remote %s:%d:%d", addr.c_str(), port, family);
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
		}

	}

	names.clear();
	config->subKeys(path + "/dnet/allow/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		allow_list_.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/deny/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		deny_list_.insert(config->asString(it->c_str()));
	}


	{
		std::string groups = config->asString(path + "/dnet/groups", "");

		Separator sep(":");
		Tokenizer tok(groups, sep);

		for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
			try {
				elconf.groups.push_back(boost::lexical_cast<int>(*it));
			}
			catch (...) {
				log()->error("invalid dnet group id %s", it->c_str());
			}
		}
	}

	elconf.success_copies_num = config->asInt(
				path + "/dnet/success-copies-num", elconf.groups.size());

	names.clear ();
	config->subKeys(path + "/dnet/typemap/type", names);

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		std::string match = config->asString(it->c_str());

		std::string::size_type pos = match.find("->");
		std::string extention = match.substr(0, pos);
		std::string type = match.substr(pos + sizeof ("->") - 1, std::string::npos);

		typemap_[extention] = type;
	}

	// TODO:
	//expires_ = config->asInt(path + "/dnet/expires-time", 0);

	elconf.metabase_write_addr = config->asString(path + "/dnet/metabase/write-addr", "");
	elconf.metabase_read_addr = config->asString(path + "/dnet/metabase/read-addr", "");

	elconf.cocaine_config = config->asString (path + "/dnet/cocaine_config", "");

	// TODO:
	//std::string			ns;
	//int					group_weights_refresh_period;

	names.clear ();
	config->subKeys (path + "/embed_processors/processor", names);
	for (std::vector<std::string>::iterator it = names.begin (), end = names.end (); end != it; ++it) {
		EmbedProcessorModuleBase *processor = context ()->findComponent <EmbedProcessorModuleBase> (config->asString (*it + "/name"));
		if (!processor) {
			log()->error ("Embed processor %s doesn't exists in config", config->asString(*it + "/name").c_str());
		} else {
			embed_processors_.insert (std::make_pair (config->asInt (*it + "/type"), processor));
		}
	}

	names.clear ();
	config->subKeys (path + "/dnet/allow-origin/domains/domain", names);
	for (std::vector <std::string>::iterator it = names.begin (), end = names.end (); end != it; ++it) {
		allow_origin_domains_.insert (config->asString (it->c_str ()));
	}

	names.clear ();
	config->subKeys (path + "/dnet/allow-origin/handlers/handler", names);
	for (std::vector<std::string>::iterator it = names.begin (), end = names.end (); end != it; ++it) {
		allow_origin_handlers_.insert (config->asString (it->c_str ()));
	}


	log ()->debug ("HANDLE create elliptics proxy");
	ellipticsProxy_.reset (new elliptics::EllipticsProxy (elconf));
	log ()->debug ("HANDLE elliptics proxy is created");

	//
	registerHandler ("upload", &Proxy::uploadHandler);
	registerHandler ("get", &Proxy::getHandler);
	registerHandler ("delete", &Proxy::deleteHandler);
	registerHandler ("download-info", &Proxy::downloadInfoHandler);
	registerHandler ("bulk-write", &Proxy::bulkUploadHandler);
	registerHandler ("bulk-read", &Proxy::bulkGetHandler);

	log ()->debug ("HANDLE handles are registred");
}

void Proxy::onUnload () {
	ComponentBase::onUnload ();
}

void Proxy::handleRequest (fastcgi::Request *request, fastcgi::HandlerContext *context) {
	(void)context;
	log ()->debug ("Handling request: %s", request->getScriptName ().c_str ());

	try {
		std::string handler;
		if (request->getQueryString().length() != 0) {
			if (request->hasArg("direct")) {
				handler = "get";
			} else if (request->hasArg("unlink")) {
				handler = "delete";
			}
#if 0
			else if (request->hasArg("stat") || request->hasArg("ping")) {
				handler = "stat";
			}
			else if (request->hasArg("stat_log")) {
				handler = "stat-log";
			}
			else if (request->hasArg("range")) {
				handler = "range";
			}
			else if (request->hasArg("range-delete")) {
				handler = "range-delete";
			}
			else if (request->hasArg("bulk-read")) {
				handler = "bulk-read";
			}
			else if (request->hasArg("bulk-write")) {
				handler = "bulk-write";
			}
			else if (request->hasArg("exec-script")) {
				handler = "exec-script";
			}
#endif
			else {
				if (request->hasArg("name")) {
					handler = request->getServerPort() == write_port_ ? "upload" : "download-info";
				}
				else {
					handler = request->getScriptName().substr(1, std::string::npos);
				}
			}
		}
		else {
			handler = request->getScriptName().substr(1, std::string::npos);
		}
		std::string::size_type pos = handler.find('/');
		handler = handler.substr(0, pos);
		RequestHandlers::iterator it = handlers_.find(handler);
		if (handlers_.end() == it) {
			log ()->debug ("Handle for <%s> request not found",
						   handler.c_str ());
			throw fastcgi::HttpException(404);

			/*request->setStatus (200);
			request->setContentType ("text/plain");

			std::stringstream ss;
			ss << "Script name: " << request->getScriptName () << std::endl
			   << "Handler: " << handler << std::endl;

			for (RequestHandlers::iterator it = handlers_.begin ();
				 it != handlers_.end (); ++it) {
				ss << it->first << '\t' << it->second << std::endl;
			}

			std::string content = ss.str ();

			request->setHeader ("Content-Length",
								boost::lexical_cast <std::string> (content.length ()));
			request->write (content.c_str (), content.length ());
			request->setHeader ("Data", content);
			return;*/
		}

		if (allow_origin_handlers_.end() != allow_origin_handlers_.find(handler)) {
			allowOrigin(request);
		}

		log ()->debug ("Process request <%s>", handler.c_str ());
		(this->*it->second)(request);
	}
	catch (const fastcgi::HttpException &e) {
		log ()->debug ("Exception: %s", e.what ());
		throw;
	}
	catch (...) {
		log ()->debug ("Exception: unknown");
		throw fastcgi::HttpException(501);
	}
}

void Proxy::registerHandler (const char *name, Proxy::RequestHandler handler) {
	bool was_inserted = handlers_.insert (std::make_pair (name, handler)).second;
	if (!was_inserted) {
		log ()->error ("Repeated registration of %s handler", name);
	}
}

void Proxy::uploadHandler(fastcgi::Request *request) {
	//boost::optional <elliptics::Key> key;
	elliptics::Key key = getKey (request);
	uint64_t size;

	uint64_t offset = request->hasArg ("offset") ? boost::lexical_cast <uint64_t> (request->getArg ("offset")) : 0;
	unsigned int cflags = request->hasArg ("cflags") ? boost::lexical_cast <unsigned int> (request->getArg ("cflags")) : 0;
	unsigned int ioflags = request->hasArg ("ioflags") ? boost::lexical_cast <unsigned int> (request->getArg ("ioflags")) : 0;

	std::vector<int> groups;

	int replication_count = request->hasArg ("replication-count") ? boost::lexical_cast <int> (request->getArg ("replication-count")) : 0;

	bool embed = request->hasArg ("embed") || request->hasArg ("embed_timestamp");
	time_t ts;
	try {
		ts = request->hasArg("timestamp") ? boost::lexical_cast<uint64_t>(request->getArg("timestamp")) : 0;
	} catch (...) {
		log ()->error ("Incorrect timestamp");
		//throw fastcgi::HttpException (503);
		request->setStatus (503);
		return;
	}

	try {
		getGroups (request, groups, replication_count);
	} catch (const std::exception &e) {
		log ()->error ("Exception: %s", e.what ());
		//throw fastcgi::HttpException (503);
		request->setStatus (503);
		return;
	}

	if (!key.byId ()) {
		if (request->hasArg ("prepare")) {
			size = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
			ioflags |= DNET_IO_FLAGS_PREPARE;
		} else if (request->hasArg ("commit")) {
			size = 0;
			ioflags |= DNET_IO_FLAGS_COMMIT;
		} else if (request->hasArg ("plain_write") || request->hasArg ("plain-write")) {
			size = 0;
			ioflags |= DNET_IO_FLAGS_PLAIN_WRITE;
		} else {
			size = 0;
		}
	}

	//std::vector <boost::shared_ptr <elliptics::embed> > embeds;
	std::ostringstream oss (std::ios_base::binary | std::ios_base::out);

	if (embed) {
		bwriteToSS <uint32_t> (oss, EmbedProcessorModuleBase::DNET_FCGI_EMBED_TIMESTAMP);
		bwriteToSS <uint32_t> (oss, 0);
		bwriteToSS <uint32_t> (oss, sizeof (uint32_t));
		bwriteToSS <time_t> (oss, ts);

		bwriteToSS <uint32_t> (oss, EmbedProcessorModuleBase::DNET_FCGI_EMBED_DATA);
		bwriteToSS <uint32_t> (oss, 0);
		bwriteToSS <uint32_t> (oss, 0);
	}

	std::string data;
	request->requestBody ().toString (data);
	data = oss.str ().append (data);

	try {
		using namespace elliptics;
		std::vector <LookupResult> l =  ellipticsProxy_->write (
					key, data,
					_offset = offset, _size = size, _cflags = cflags,
					_ioflags = ioflags, _groups = groups,
					_replication_count = replication_count/*,
					_embeds = embeds*/);
		log ()->debug ("HANDLER upload success");

		request->setStatus (200);

		std::stringstream ss;
		ss << "written " << l.size() << " copies" << std::endl;
		for (std::vector<LookupResult>::const_iterator it = l.begin ();
			 it != l.end (); ++it) {
			ss << "\tgroup: " << it->group << "\tpath: " << it->hostname
			   << ":" << it->port << it->path << std::endl;
		}

		std::string str = ss.str ();

		request->setContentType ("text/plaint");
		request->setHeader ("Context-Lenght",
							boost::lexical_cast <std::string> (
								str.length ()));
		request->write (str.c_str (), str.size ());
	} catch (const std::exception &e) {
		log ()->error("Exception: %s", e.what());
		request->setStatus (503);
	} catch (...) {
		log ()->error("Eexception: unknown");
		request->setStatus (503);
	}
}

void Proxy::getHandler(fastcgi::Request *request) {
	elliptics::Key key = getKey (request);

	std::string content_type;
	{
		std::string filename = getFilename (request);
		std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

		if (deny_list_.find(extention) != deny_list_.end() ||
			(deny_list_.find("*") != deny_list_.end() &&
			allow_list_.find(extention) == allow_list_.end())) {
			throw fastcgi::HttpException(403);
		}

		std::map<std::string, std::string>::iterator it = typemap_.find(extention);

		if (typemap_.end() == it) {
			content_type = "application/octet";
		} else {
			content_type = it->second;
		}
	}

	uint64_t offset = request->hasArg ("offset") ? boost::lexical_cast <uint64_t> (request->getArg ("offset")) : 0;
	unsigned int cflags = request->hasArg ("cflags") ? boost::lexical_cast <unsigned int> (request->getArg ("cflags")) : 0;
	unsigned int ioflags = request->hasArg ("ioflags") ? boost::lexical_cast <unsigned int> (request->getArg ("ioflags")) : 0;
	uint64_t size = request->hasArg ("size") ? boost::lexical_cast <uint64_t> (request->getArg ("size")) : 0;

	std::vector<int> groups;

	try {
		getGroups (request, groups);
	} catch (const std::exception &e) {
		log ()->error ("Exception: %s", e.what ());
		//throw fastcgi::HttpException (503);
		request->setStatus (503);
		return;
	}


	elliptics::ReadResult result;
	{
		using namespace elliptics;
		result = ellipticsProxy_->read (key,
										_offset = offset, _cflags = cflags,
										_ioflags = ioflags, _size = size,
										_groups = groups);
	}
	request->setStatus (200);
	request->setContentType (content_type);

	std::istringstream iss (result.data, std::ios_base::binary | std::ios_base::in);

	bool embed = request->hasArg("embed") || request->hasArg("embed_timestamp");

	time_t timestamp = 0;

	if (embed) {
		uint32_t type;
		uint32_t flags;
		uint32_t size;

		do {
			breadFromSS <uint32_t> (iss, type);
			breadFromSS <uint32_t> (iss, flags);
			breadFromSS <uint32_t> (iss, size);

			if (type == EmbedProcessorModuleBase::DNET_FCGI_EMBED_TIMESTAMP) {
				breadFromSS <time_t> (iss, timestamp);
			} else if (type == EmbedProcessorModuleBase::DNET_FCGI_EMBED_DATA) {
				break;
			} else {
				auto it = embed_processors_.find (type);
				if (it != embed_processors_.end ()) {
					std::vector <char> buf (size);
					if (size != 0)
						iss.read (buf.data (), size);
					int http_status = 200;
					if (it->second->processEmbed (request, flags, buf.data (), size, http_status)) {
						request->setStatus (http_status);
						return;
					}
				}

			}
		} while (!iss.eof ());
	}

	const char * rd = result.data.data ();
	const char *b = rd + iss.tellg ();
	const char *e = rd + result.data.length ();

	char ts_str[128];
	struct tm tmp;
	strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));
	request->setHeader("Last-Modified", ts_str);

	request->setHeader ("Content-Length",
						boost::lexical_cast <std::string> (e - b));
	request->write (b, e - b);
}

void Proxy::deleteHandler(fastcgi::Request *request) {
	elliptics::Key key = getKey (request);

	std::vector<int> groups;

	if (request->hasArg ("groups")) {
		Separator sep (":");
		Tokenizer tok (request->getArg ("groups"), sep);

		try {
			for (Tokenizer::iterator it = tok.begin (), end = tok.end (); end != it; ++it) {
				groups.push_back (boost::lexical_cast<int>(*it));
			}
		}
		catch (...) {
			log ()->debug ("Exception: gorups <%s> is incorrect",
						   request->getArg ("groups").c_str ());
			throw fastcgi::HttpException(503);
		}
	}

	try {
		using namespace elliptics;
		ellipticsProxy_->remove (key, _groups = groups);
	} catch (std::exception &e) {
		log ()->error("Exception: %s", e.what());
		request->setStatus (503);
	} catch (...) {
		log ()->error("Eexception: unknown");
		request->setStatus (503);
	}
}

void Proxy::downloadInfoHandler(fastcgi::Request *request) {
	elliptics::Key key = getKey (request);
	std::vector <int> groups;

	try {
		getGroups (request, groups);
	} catch (const std::exception &e) {
		log ()->error ("Exception: %s", e.what ());
		throw fastcgi::HttpException (503);
	}

	elliptics::LookupResult lr = ellipticsProxy_->lookup (key, elliptics::_groups = groups);

	std::stringstream ss;
	ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
	std::string region = "-1";

	// TODO: add regional part

	long time;
	{
		using namespace std::chrono;
		time = duration_cast <microseconds> (
					system_clock::now ().time_since_epoch ()
					).count ();
	}

	ss << "<download-info>";
	//ss << "<ip>" << request->getRemoteAddr () << "</ip>";
	ss << "<host>" << lr.hostname << "</host>";
	ss << "<path>" << lr.path << "</path>";
	//ss << "<group>" << lr.group << "</group>";
	ss << "<region>" << region << "</region>";
	ss << "</download-info>";

	std::string str = ss.str ();

	request->setStatus (200);
	request->setContentType ("text/xml");
	request->write (str.c_str (), str.length ());
}

void Proxy::bulkUploadHandler(fastcgi::Request *request)
{
	std::vector <std::string> file_names;
	request->remoteFiles (file_names);
	std::vector <elliptics::Key> keys;
	std::vector <std::string> data;

	for (auto it = file_names.begin (), end = file_names.end (); it != end; ++it) {
		std::string content;
		request->remoteFile (*it).toString (content);
		keys.emplace_back (*it, 0);
		data.push_back (content);
	}

	unsigned int cflags = request->hasArg ("cflags") ? boost::lexical_cast <unsigned int> (request->getArg ("cflags")) : 0;
	int replication_count = request->hasArg ("replication-count") ? boost::lexical_cast <int> (request->getArg ("replication-count")) : 0;

	std::vector<int> groups;
	try {
		getGroups (request, groups, replication_count);
	} catch (const std::exception &e) {
		log ()->error ("Exception: %s", e.what ());
		request->setStatus (503);
		return;
	}

	{
		using namespace elliptics;
		auto results = ellipticsProxy_->bulk_write(keys, data, _cflags = cflags, _replication_count = replication_count, _groups = groups);


		request->setStatus (200);

		std::ostringstream oss;
		oss << "writte result: " << std::endl;

		for (auto it = results.begin (), end = results.end (); it != end; ++it) {
			oss << it->first.str () << ':' << std::endl;
			for (auto it2 = it->second.begin (), end2 = it->second.end (); it2 != end2; ++it2) {
				oss << "\tgroup: " << it2->group << "\tpath: " << it2->hostname
									  << ":" << it2->port << it2->path << std::endl;
			}
		}

		std::string str = oss.str ();

		request->setContentType ("text/plaint");
		request->setHeader ("Context-Lenght",
							boost::lexical_cast <std::string> (
								str.length ()));
		request->write (str.c_str (), str.size ());
	}
}

void Proxy::bulkGetHandler(fastcgi::Request *request)
{
	std::string keys_str;
	request->requestBody ().toString (keys_str);
	std::vector <elliptics::Key> keys;

	Separator sep("\n");
	Tokenizer tok(keys_str, sep);

	try {
		for (auto it = tok.begin (), end = tok.end (); it != end; ++it) {
			keys.push_back (*it);
		}
	}
	catch (...) {
		log()->error("invalid keys list: %s", keys_str.c_str());
	}

	unsigned int cflags = request->hasArg ("cflags") ? boost::lexical_cast <unsigned int> (request->getArg ("cflags")) : 0;
	std::vector<int> groups;
	try {
		getGroups (request, groups);
	} catch (const std::exception &e) {
		log ()->error ("Exception: %s", e.what ());
		request->setStatus (503);
		return;
	}

	try {
		auto result = ellipticsProxy_->bulk_read (keys, elliptics::_cflags = cflags, elliptics::_groups = groups);

		request->setStatus (200);
		request->setContentType ("text/html");
		request->setHeader ("Transfer-Encoding", "chunked");

		std::ostringstream oss (std::ios_base::binary | std::ios_base::out);
		//unsigned char CRLF [2] = {0x0D, 0x0A};
		char CRLF [] = "\r\n";
		for (auto it = result.begin (), end = result.end (); it != end; ++it) {
			size_t size = it->second.data.length ();
			oss << std::hex << size << "; name=\"" << it->first.str () << "\"" << CRLF;
			oss << it->second.data << CRLF;
		}
		oss << 0 << CRLF << CRLF;
		std::string body = oss.str ();
		request->write (body.data (), body.length ());
	} catch (const std::exception &e) {
		log ()->error ("Exception during bulk-read: %s", e.what ());
		request->setStatus (503);
	} catch (...) {
		log ()->error ("Exception during bulk-read: unknown");
		request->setStatus (503);
	}
}

void Proxy::allowOrigin(fastcgi::Request *request) const {
	if (0 == allow_origin_domains_.size ()) {
		return;
	}

	if (!request->hasHeader ("Origin")) {
		return;
	}

	std::string domain = request->getHeader ("Origin");
	if (!domain.compare (0, sizeof ("http://") - 1, "http://")) {
		domain = domain.substr(sizeof ("http://") - 1, std::string::npos);
	}

	for (std::set<std::string>::const_iterator it = allow_origin_domains_.begin (), end = allow_origin_domains_.end ();
		 end != it; ++it) {
		std::string allow_origin_domain = *it;

		if (domain.length () < allow_origin_domain.length () - 1) {
			continue;
		}

		bool allow = false;

		if (domain.length () == allow_origin_domain.length () - 1) {
			allow = !allow_origin_domain.compare (1, std::string::npos, domain);
		}
		else {
			allow = !domain.compare(domain.length () - allow_origin_domain.length (), std::string::npos, allow_origin_domain);
		}

		if (allow) {
			domain = (!request->getHeader ("Origin").compare(0, sizeof ("https://") - 1, "https://") ? "https://" : "http://") + domain;
			request->setHeader ("Access-Control-Allow-Origin", domain);
			request->setHeader ("Access-Control-Allow-Credentials", "true");
			return;
		}
	}
	throw fastcgi::HttpException (403);
}

FCGIDAEMON_REGISTER_FACTORIES_BEGIN()
FCGIDAEMON_ADD_DEFAULT_FACTORY("proxy_factory", Proxy)
FCGIDAEMON_REGISTER_FACTORIES_END()
