#ifndef EMBED_PROCESSOR_MODULE
#define EMBED_PROCESSOR_MODULE

#include <fastcgi2/request.h>
#include <fastcgi2/logger.h>

#include <cstdint>

#include "component_base.hpp"

class EmbedProcessorModuleBase : public ComponentBase {
public:
	EmbedProcessorModuleBase(fastcgi::ComponentContext *context);
	virtual ~EmbedProcessorModuleBase();

	virtual void onLoad();
	virtual void onUnload();

	virtual bool processEmbed(fastcgi::Request *request, uint32_t flags, char *data, uint32_t size, int &http_status);

	const static uint32_t DNET_FCGI_EMBED_DATA = 1;
	const static uint32_t DNET_FCGI_EMBED_TIMESTAMP = 2;

protected:
	fastcgi::Logger* log() const;

private:
	fastcgi::Logger *logger_;
};

#endif /* EMBED_PROCESSOR_MODULE */
