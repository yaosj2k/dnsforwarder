#ifndef _READCONFIG_
#define _READCONFIG_

#include <stdio.h>
#include "common.h"

/* A valid line of a configuration file has the following structure:
 *  <Option> <value>
 * Which `<Option>' is the name of a option, and here we call it `KEY NAME'.
 * And `<value>' is the option's value, we just call it `value'.
 * A line started with `#' is a comment, which will be ignored when it is read.
 * A valid option can be followed a comment which will be ignored too:
 *  <Option> <value> # I'm comment.
 *
 */

/* Set the max length of a key name */
#define	KEY_NAME_MAX_SIZE	64

/* Set the max length of a option's caption */
#define	CAPTION_MAX_SIZE	128
/* Each option can have a caption, which is a kind of explanatory text. */

/* A value must have a type. Here we just need these three types. */
typedef enum _OptionType{
	TYPE_UNDEFINED = 0,
	TYPE_INT32,
	TYPE_BOOLEAN,
	TYPE_STRING
} OptionType;

typedef enum _MultilineStrategy{
	STRATEGY_UNKNOWN = 0,
	STRATEGY_REPLACE,
	STRATEGY_APPEND,
	STRATEGY_APPEND_DISCARD_DEFAULT
} MultilineStrategy;

typedef union _VType{
	char		*str;
	int			INT32;
	BOOL		boolean;
} VType;

typedef enum _OptionStatus{
	STATUS_UNUSED = 0,
	STATUS_DEFAULT_VALUE,
	STATUS_SPECIAL_VALUE
}OptionStatus;

/* An option */
typedef struct _Option{
	/* Designate if this option is used. */
	OptionStatus	Status;

	/* Name */
	char		KeyName[KEY_NAME_MAX_SIZE + 1];


	MultilineStrategy	Strategy;

	/* Type */
	OptionType	Type;

	/* Value holder */
	VType		Holder;

	/* Caption */
	char		Caption[CAPTION_MAX_SIZE + 1];
} ConfigOption;

/* The exposed type(The infomations about a configuration file) to read options from a configuration file. */
typedef struct _ConfigFileInfo{

	/* Static, once inited, never changed. */
	FILE			*fp;

	/* An array of all the options. */
	ConfigOption	*Options;

	/* The number of options. */
	int			NumOfOptions;

} ConfigFileInfo;

void ConfigInitInfo(ConfigFileInfo *Info);

int ConfigOpenFile(ConfigFileInfo *Info, const char *File);

int ConfigCloseFile(ConfigFileInfo *Info);

int ConfigAddOption(ConfigFileInfo *Info, char *KeyName, MultilineStrategy Strategy, OptionType Type, VType Initial, char *Caption);

int ConfigRead(ConfigFileInfo *Info);

const char *ConfigGetString(ConfigFileInfo *Info, char *KeyName);

int ConfigGetInt32(ConfigFileInfo *Info, char *KeyName);

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName);

void ConfigSetValue(ConfigFileInfo *Info, VType Value, char *KeyName);

void ConfigDisplay(ConfigFileInfo *Info);

#endif // _READCONFIG_
