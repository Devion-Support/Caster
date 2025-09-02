#ifndef CASTER_HELPERS_H
#define CASTER_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks if a file exists at the given path.
 */
int fileExists(const char *fname);

/**
 * @brief Checks if a file is readable.
 */
int isFileReadable(const char *fname);

/**
 * @brief Checks if a file is executable.
 */
int isFileExecutable(const char *fname);

/**
 * @brief Reads content of a file.
 */
char* readFile(const char *fname);

/**
 * @brief Gets system property value.
 */
char* getSystemProperty(const char *property);

#ifdef __cplusplus
}
#endif

#endif //CASTER_HELPERS_H