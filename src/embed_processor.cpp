#include "embed_processor.hpp"

#include <fastcgi2/config.h>

#include <stdexcept>

EmbedProcessorModuleBase::EmbedProcessorModuleBase (fastcgi::ComponentContext *context)
	: ComponentBase (context)
	, logger_ (0) {
}

EmbedProcessorModuleBase::~EmbedProcessorModuleBase () {
}

void
EmbedProcessorModuleBase::onLoad () {
	assert (0 == logger_);

	const fastcgi::Config *config = context ()->getConfig ();
	std::string path (context ()->getComponentXPath ());

	logger_ = context ()->findComponent <fastcgi::Logger> (config->asString (path + "/logger"));
	if (!logger_) {
		throw std::logic_error ("can't find logger");
	}
}

void
EmbedProcessorModuleBase::onUnload () {
}

bool EmbedProcessorModuleBase::processEmbed(fastcgi::Request *request, uint32_t flags, char *data, uint32_t size, int &http_status) {
	(void)request;
	(void)flags;
	(void)data;
	http_status = 200;
	return true;
}

fastcgi::Logger *EmbedProcessorModuleBase::log () const {
	return logger_;
}
