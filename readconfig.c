#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"
#include "readline.h"

void ConfigInitInfo(ConfigFileInfo *Info)
{
	Info -> fp = NULL;
	Info -> Options = NULL;
	Info -> NumOfOptions = 0;
}

int ConfigOpenFile(ConfigFileInfo *Info, const char *File)
{
	Info -> fp = fopen(File, "r");
	if( Info -> fp == NULL )
		return GET_LAST_ERROR();
	else
		return 0;
}

int ConfigCloseFile(ConfigFileInfo *Info)
{
	return fclose(Info -> fp);
}

int ConfigAddOption(ConfigFileInfo *Info, char *KeyName, MultilineStrategy Strategy, OptionType Type, VType Initial, char *Caption)
{
	int loop;

	if( strlen(KeyName) > sizeof(Info -> Options -> KeyName) - 1 )
	{
		return -1;
	}

	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if(Info -> Options[loop].Status == STATUS_UNUSED)
			break;
	}

	if(loop == Info -> NumOfOptions)
	{
		int loop2;

		if( SafeRealloc((void *)&(Info -> Options), (Info -> NumOfOptions + 10) * sizeof(ConfigOption)) != 0)
		{
			return 1;
		}

		(Info -> NumOfOptions) += 10;

		for(loop2 = loop; loop2 != Info -> NumOfOptions; ++loop2)
			Info -> Options[loop2].Status = STATUS_UNUSED;
	}

	strcpy(Info -> Options[loop].KeyName, KeyName);
	Info -> Options[loop].Type = Type;
	Info -> Options[loop].Status = STATUS_DEFAULT_VALUE;
	if( Caption != NULL )
	{
		strncpy(Info -> Options[loop].Caption, Caption, CAPTION_MAX_SIZE);
		Info -> Options[loop].Caption[CAPTION_MAX_SIZE] = '\0';
	} else {
		*(Info -> Options[loop].Caption) = '\0';
	}

	switch( Type )
	{
		case TYPE_INT32:
		case TYPE_BOOLEAN:
			Info -> Options[loop].Holder = Initial;
			break;

		case TYPE_STRING:
			if(Initial.str != NULL)
			{
				Info -> Options[loop].Holder.str = SafeMalloc(strlen(Initial.str) + 1);
				strcpy(Info -> Options[loop].Holder.str, Initial.str);
			} else {
				Info -> Options[loop].Holder.str = NULL;
			}
			Info -> Options[loop].Strategy = Strategy;
			break;

		default:
			break;
	}

	return 0;
}

static ConfigOption *GetOptionOfAInfo(const ConfigFileInfo *Info, const char *KeyName)
{
	int	loop;

	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if(strcmp(KeyName, Info -> Options[loop].KeyName) == 0)
			return Info -> Options + loop;
	}
	return NULL;
}

static char *GetKeyNameFromLine(const char *Line, char *Buffer)
{
	const char	*itr = Line;
	const char	*SpacePosition;

	for(; isspace(*itr); ++itr);

	SpacePosition = strchr(itr, ' ');

	if(SpacePosition == NULL)
		return NULL;

	strncpy(Buffer, itr, SpacePosition - Line);
	Buffer[SpacePosition - Line] = '\0';

	return Buffer;
}

static const char *GetValuePosition(const char *Line)
{
	const char	*itr = Line;

	for(; isspace(*itr); ++itr);

	itr = strchr(itr, ' ');

	if(itr == NULL)
		return NULL;

	for(; isspace(*itr) && *itr != '\0'; ++itr);

	if( *itr == '\0' )
		return NULL;
	else
		return itr;
}

int ConfigRead(ConfigFileInfo *Info)
{
	int				NumOfRead	=	0;

	char			Buffer[3072];
	char			*ValuePos;
	ReadLineStatus	ReadStatus;

	char			KeyName[KEY_NAME_MAX_SIZE + 1];
	ConfigOption	*Option;

	while(TRUE){
		ReadStatus = ReadLine(Info -> fp, Buffer, sizeof(Buffer));
		if( ReadStatus == READ_FAILED_OR_END )
			return NumOfRead;

		if( GetKeyNameFromLine(Buffer, KeyName) == NULL )
			continue;

		Option = GetOptionOfAInfo(Info, KeyName);
		if( Option == NULL )
			continue;

		ValuePos = (char *)GetValuePosition(Buffer);
		if( ValuePos == NULL )
			continue;

		switch( Option -> Type )
		{
			case TYPE_INT32:
				sscanf(ValuePos, "%d", &(Option -> Holder.INT32));
				break;

			case TYPE_BOOLEAN:
				if( isdigit(*ValuePos) )
				{
					if( *ValuePos == '0' )
						Option -> Holder.boolean = FALSE;
					else
						Option -> Holder.boolean = TRUE;
				} else {
					StrToLower(ValuePos);

					if( strstr(ValuePos, "false") != NULL )
						Option -> Holder.boolean = FALSE;
					else if( strstr(ValuePos, "true") != NULL )
						Option -> Holder.boolean = TRUE;

					if( strstr(ValuePos, "no") != NULL )
						Option -> Holder.boolean = FALSE;
					else if( strstr(ValuePos, "yes") != NULL )
						Option -> Holder.boolean = TRUE;
				}
				break;

			case TYPE_STRING:
				{
					char *result;

					switch (Option -> Strategy)
					{
						case STRATEGY_UNKNOWN:
							continue;
							break;

						case STRATEGY_APPEND_DISCARD_DEFAULT:
							if( Option -> Status == STATUS_DEFAULT_VALUE )
							{
								Option -> Strategy = STRATEGY_APPEND;
							}
							/* No break */

						case STRATEGY_REPLACE:
							if( Option -> Holder.str != NULL )
							{
								SafeFree(Option -> Holder.str);
							}

							result = SafeMalloc(strlen(ValuePos) + 1);
							if( result == NULL )
							{
								continue;
							}

							strcpy(result, ValuePos);
							Option -> Status = STATUS_SPECIAL_VALUE;
							break;

						case STRATEGY_APPEND:
							if( Option -> Holder.str != NULL )
							{
								result = SafeMalloc(strlen(Option -> Holder.str) + strlen(ValuePos) + 2);
								if( result == NULL )
								{
									continue;
								}
								strcpy(result, Option -> Holder.str);
								strcat(result, ",");
								strcat(result, ValuePos);
								SafeFree(Option -> Holder.str);
							} else {
								result = SafeMalloc(strlen(ValuePos) + 1);
								if( result == NULL )
								{
									continue;
								}
								strcpy(result, ValuePos);
							}
							Option -> Status = STATUS_SPECIAL_VALUE;
							break;

							default:
								continue;
								break;
					}

					while( ReadStatus != READ_DONE ){

						ReadStatus = ReadLine(Info -> fp, Buffer, sizeof(Buffer));
						if( ReadStatus == READ_FAILED_OR_END )
							break;
						if( SafeRealloc((void *)&result, strlen(result) + strlen(Buffer) + 1) != 0 )
							break;
						strcat(result, Buffer);
					}

					if( strlen(result) != 0 )
					{
						int loop = strlen(result) - 1;

						while( result[loop] == '\n' || result[loop] == '\r' )
						{
							result[loop] = '\0';
							--loop;
						}
					}

					Option -> Holder.str = result;
				}
				break;

			default:
				break;
		}
		++NumOfRead;
	}
	return NumOfRead;
}

const char *ConfigGetString(ConfigFileInfo *Info, char *KeyName)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( Info -> Options[loop].Type == TYPE_STRING && strncmp(Info -> Options[loop].KeyName, KeyName, KEY_NAME_MAX_SIZE) == 0 )
			return Info -> Options[loop].Holder.str;
	}
	return 0;
}

int ConfigGetInt32(ConfigFileInfo *Info, char *KeyName)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( Info -> Options[loop].Type == TYPE_INT32 && strncmp(Info -> Options[loop].KeyName, KeyName, KEY_NAME_MAX_SIZE) == 0 )
			return Info -> Options[loop].Holder.INT32;
	}
	return 0;
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( Info -> Options[loop].Type == TYPE_BOOLEAN && strncmp(Info -> Options[loop].KeyName, KeyName, KEY_NAME_MAX_SIZE) == 0 )
			return Info -> Options[loop].Holder.boolean;
	}
	return 0;
}

void ConfigSetValue(ConfigFileInfo *Info, VType Value, char *KeyName)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( strncmp(Info -> Options[loop].KeyName, KeyName, KEY_NAME_MAX_SIZE) == 0 )
		{
			Info -> Options[loop].Holder = Value;
			break;
		}
	}
}

void ConfigDisplay(ConfigFileInfo *Info)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( *(Info -> Options[loop].Caption) != '\0' )
		{
			switch( Info -> Options[loop].Type )
			{
				case TYPE_INT32:
					printf("%s:%d\n", Info -> Options[loop].Caption, Info -> Options[loop].Holder.INT32);
					break;
				case TYPE_BOOLEAN:
					printf("%s:%s\n", Info -> Options[loop].Caption, BoolToYesNo(Info -> Options[loop].Holder.boolean));
					break;
				case TYPE_STRING:
					if( Info -> Options[loop].Holder.str != NULL )
						printf("%s:%s\n", Info -> Options[loop].Caption, Info -> Options[loop].Holder.str);
					break;
				default:
					break;
			}
		}
	}
}
