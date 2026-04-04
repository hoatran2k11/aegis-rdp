#ifndef PARSER_H
#define PARSER_H

int ExtractXmlElementValue(const char *xml, const char *tag, char *out, int outSize);

int ExtractXmlDataValue(const char *xml, const char *name, char *out, int outSize);

#endif /* PARSER_H */
