#include "component_base.hpp"
#include <fastcgi2/config.h>
#include <stdexcept>

ComponentBase::ComponentBase (fastcgi::ComponentContext * context)
	: fastcgi::Component (context)
	, logger_ (0)
{}

ComponentBase::~ComponentBase() {
}

void ComponentBase::onLoad() {
	assert (0 == logger_);

	const fastcgi::Config *config = context ()->getConfig ();
	std::string path (context ()->getComponentXPath ());

	logger_ = context ()->findComponent <fastcgi::Logger> (config->asString (path + "/logger"));
	if (!logger_) {
		throw std::logic_error ("can't find logger");
	}
}

void ComponentBase::onUnload() {
}

fastcgi::Logger *ComponentBase::log() const {
	return logger_;
}
