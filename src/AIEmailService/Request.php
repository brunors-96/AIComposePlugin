<?php

namespace HercegDoo\AIComposePlugin\AIEmailService;

final class Request
{
    /**
     * @param null|array<string, mixed>|string $default
     *
     * @return null|array<string, mixed>|string
     */
    public static function post(string $key, $default = null)
    {
        return self::input($key, $default, \rcube_utils::INPUT_POST);
    }

    /**
     * @param null|array<string, mixed>|string $default
     *
     * @return null|array<string, mixed>|string
     */
    public static function get(string $key, $default = null)
    {
        return self::input($key, $default, \rcube_utils::INPUT_GET);
    }

    public static function postString(string $key, ?string $default = null): ?string
    {
        $data = self::post($key, $default);
        if (\is_array($data)) {
            return null;
        }

        return $data;
    }

    /**
     * @param null|array<string, mixed>|string $default
     *
     * @return null|array<string, mixed>|string
     */
    private static function input(string $key, $default = null, int $source = \rcube_utils::INPUT_POST)
    {
        $data = \rcube_utils::get_input_value($key, $source);
        $data = $data === '' ? null : $data;
        if ($data === null) {
            return $default;
        }

        // Sanitização para prevenir injeção de código
        if (is_string($data)) {
            $data = trim($data);
            // Limitar tamanho da entrada para prevenir DoS
            if (strlen($data) > 10000) {
                throw new \InvalidArgumentException('Input too long');
            }
        }

        return $data;
    }
}
