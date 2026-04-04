#include "include/parser.h"
#include <string.h>
#include <stdio.h>

int ExtractXmlElementValue(const char *xml, const char *tag, char *out, int outSize) {
    if (!xml || !tag || !out || outSize <= 0) return 0;
    char openTag[128];
    char closeTag[128];
    snprintf(openTag, sizeof(openTag), "<%s", tag);
    snprintf(closeTag, sizeof(closeTag), "</%s>", tag);

    const char *start = strstr(xml, openTag);
    if (!start) return 0;
    start = strchr(start, '>');
    if (!start) return 0;
    start++;

    const char *end = strstr(start, closeTag);
    if (!end) return 0;

    int len = (int)(end - start);
    if (len >= outSize) len = outSize - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return len;
}

int ExtractXmlDataValue(const char *xml, const char *name, char *out, int outSize) {
    if (!xml || !name || !out || outSize <= 0) return 0;
    const char *pos = xml;
    size_t name_len = strlen(name);
    while ((pos = strstr(pos, "<Data Name=")) != NULL) {
        const char *quote = pos + 11;
        char quoteChar = *quote;
        if (quoteChar != '"' && quoteChar != '\'') { pos += 10; continue; }
        const char *nameStart = quote + 1;
        const char *nameEnd = strchr(nameStart, quoteChar);
        if (!nameEnd) break;
        int nameLen = (int)(nameEnd - nameStart);
        if (nameLen == (int)name_len && strncmp(nameStart, name, nameLen) == 0) {
            const char *valueStart = nameEnd + 1;
            if (*valueStart != '>') return 0;
            valueStart++;
            const char *valueEnd = strstr(valueStart, "</Data>");
            if (!valueEnd) return 0;
            int len = (int)(valueEnd - valueStart);
            if (len >= outSize) len = outSize - 1;
            memcpy(out, valueStart, len);
            out[len] = '\0';
            return len;
        }
        pos = nameEnd + 1;
    }
    return 0;
}
