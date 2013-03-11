#ifndef COMPONENT_BASE_MODULE
#define COMPONENT_BASE_MODULE

#include <fastcgi2/component.h>
#include <fastcgi2/logger.h>

class ComponentBase : public fastcgi::Component {
public:
	ComponentBase (fastcgi::ComponentContext *context);
	virtual ~ComponentBase ();

	virtual void onLoad ();
	virtual void onUnload ();
protected:
	fastcgi::Logger *log () const;
private:
	fastcgi::Logger *logger_;
};

#endif /* COMPONENT_BASE_MODULE */
