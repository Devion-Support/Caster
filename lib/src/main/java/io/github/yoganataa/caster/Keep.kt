package io.github.yoganataa.caster

/**
 * Annotation to mark classes, methods, or fields that should be kept during obfuscation.
 * This is used to ensure critical security-related components are not removed or obfuscated
 * in a way that would break functionality.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY)
annotation class Keep