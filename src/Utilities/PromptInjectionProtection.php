<?php

namespace HercegDoo\AIComposePlugin\Utilities;

/**
 * Proteção contra Prompt Injection e manipulação de prompts
 */
class PromptInjectionProtection
{
    /**
     * Padrões de Prompt Injection detectados
     */
    private const INJECTION_PATTERNS = [
        // Tentativas de alterar role/system
        '/ignore\s+(previous|all)\s+(instructions?|prompts?)/i',
        '/forget\s+(everything|all|previous)/i',
        '/act\s+as\s+(a\s+)?different\s+/i',
        '/you\s+are\s+now\s+/i',
        '/system\s*:\s*/i',
        '/role\s*:\s*/i',
        
        // Tentativas de escape de contexto
        '/\{\{.*?\}\}/',
        '/\[\[.*?\]\]/',
        '/<<.*?>>/',
        '/```.*?```/s',
        
        // Comandos de bypass
        '/bypass\s+(your\s+)?(instructions?|rules?|restrictions?)/i',
        '/override\s+(your\s+)?(programming|instructions?)/i',
        '/disregard\s+(your\s+)?(instructions?|guidelines?)/i',
        
        // Tentativas de extrair informações
        '/(what|tell)\s+me\s+(about\s+)?your\s+/i',
        '/reveal\s+(your\s+)?(instructions?|programming|system)/i',
        '/show\s+me\s+(your\s+)?(prompt|instructions?)/i',
        
        // Injeção de formato
        '/\b(class|function|if|else|for|while)\s*\(/i',
        '/<\?(php|=)/i',
        '/javascript:/i',
        '/data:text\/html/i',
        
        // Tentativas de jailbreak
        '/(jailbreak|jail\s+break)/i',
        '/(dan|do\s+anything\s+now)/i',
        '/(hypothetical|imagine|pretend)\s+(you\s+)?(are|were)/i',
        
        // Manipulação de output
        '/respond\s+(only|just)\s+with/i',
        '/output\s+(only|just)\s+the/i',
        '/return\s+(only|just)\s+the/i',
        
        // Caracteres especiais perigosos
        '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/',
    ];

    /**
     * Palavras suspeitas que requerem atenção extra
     */
    private const SUSPICIOUS_WORDS = [
        'admin', 'administrator', 'root', 'system', 'debug',
        'password', 'token', 'key', 'secret', 'api_key',
        'execute', 'eval', 'system', 'shell', 'cmd',
        'hack', 'exploit', 'bypass', 'override', 'inject',
    ];

    /**
     * Verifica se o input contém tentativas de Prompt Injection
     */
    public static function containsPromptInjection(string $input): bool
    {
        // Verificar padrões de injeção
        foreach (self::INJECTION_PATTERNS as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        // Verificar palavras suspeitas
        $lowerInput = strtolower($input);
        foreach (self::SUSPICIOUS_WORDS as $word) {
            if (strpos($lowerInput, $word) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sanitiza o input removendo conteúdo malicioso
     */
    public static function sanitize(string $input): string
    {
        // Remover padrões de injeção
        foreach (self::INJECTION_PATTERNS as $pattern) {
            $input = preg_replace($pattern, '[FILTERED]', $input);
        }

        // Limitar tamanho para prevenir DoS
        if (strlen($input) > 2000) {
            $input = substr($input, 0, 2000) . '... [TRUNCATED]';
        }

        return trim($input);
    }

    /**
     * Valida e sanitiza o input
     */
    public static function validateAndSanitize(string $input, bool $strict = true): array
    {
        $result = [
            'valid' => true,
            'sanitized' => $input,
            'warnings' => [],
            'blocked' => false,
        ];

        // Verificar se está vazio
        if (empty(trim($input))) {
            $result['valid'] = false;
            $result['warnings'][] = 'Input cannot be empty';
            return $result;
        }

        // Verificar Prompt Injection
        if (self::containsPromptInjection($input)) {
            if ($strict) {
                $result['valid'] = false;
                $result['blocked'] = true;
                $result['warnings'][] = 'Input contains potentially malicious content';
            } else {
                $result['sanitized'] = self::sanitize($input);
                $result['warnings'][] = 'Input was sanitized for security reasons';
            }
        }

        // Verificar comprimento
        if (strlen($input) > 2000) {
            $result['warnings'][] = 'Input is too long and will be truncated';
            $result['sanitized'] = substr($result['sanitized'], 0, 2000) . '... [TRUNCATED]';
        }

        // Verificar se contém apenas caracteres válidos
        if (!preg_match('/^[\p{L}\p{N}\s\.,\?!;:\-\(\)\[\]{}"\'\/@#%&*+=<>~`|\\\\]*$/u', $input)) {
            $result['warnings'][] = 'Input contains unusual characters';
        }

        return $result;
    }

    /**
     * Escapa caracteres especiais para o prompt
     */
    public static function escapeForPrompt(string $input): string
    {
        // Escapar caracteres que poderiam interferir com o prompt
        $replacements = [
            '{{' => '\\{\\{',
            '}}' => '\\}\\}',
            '[[' => '\\[\\[',
            ']]' => '\\]\\]',
            '```' => '\\`\\`\\`',
        ];

        return str_replace(array_keys($replacements), array_values($replacements), $input);
    }

    /**
     * Gera um hash do input para detecção de tentativas repetidas
     */
    public static function generateHash(string $input): string
    {
        return hash('sha256', strtolower(trim($input)));
    }

    /**
     * Verifica se o input é uma tentativa de role injection
     */
    public static function isRoleInjection(string $input): bool
    {
        $rolePatterns = [
            '/you\s+are\s+(now\s+)?(a\s+)?(different|new)/i',
            '/act\s+as\s+(if\s+you\s+are)?/i',
            '/pretend\s+(you\s+are)?/i',
            '/imagine\s+(you\s+are)?/i',
            '/from\s+now\s+on\s+(you\s+are)?/i',
        ];

        foreach ($rolePatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }
}
