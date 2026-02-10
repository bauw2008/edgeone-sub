<?php

function response($code, $message, $header = "")
{
    http_response_code($code);
    if ($header != "") {
        header($header);
    }
    echo $message;
    exit;
}

function download_file($url, $retry = 0)
{
    $attempt = 0;
    while ($attempt <= $retry) {
        $attempt++;
        $content = @file_get_contents($url);
        if ($content !== false) {
            return $content;
        }
    }
    response(500, "Failed to download file: $url", "Content-Type: text/plain; charset=UTF-8");
}

function load_file_to_array($file_path)
{
    $file_content = file_get_contents($file_path);
    $file_content = str_replace("\r\n", "\n", $file_content);
    $lines = explode("\n", $file_content);
    $lines = array_filter($lines);
    return $lines;
}

function load_string_to_array($string)
{
    $string = str_replace("\r\n", "\n", $string);
    $lines = explode("\n", $string);
    $lines = array_filter($lines);
    return $lines;
}

function response_nodes($node_array)
{
    $content = implode("\n", $node_array);
    $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : "";
    if ($query_string == "base64") {
        $content = base64_encode($content);
    }
    if ($query_string == "clash") {
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: text/plain; charset=UTF-8',
                'content' => $content
            ]
        ];
        $context = stream_context_create($options);
        $content = file_get_contents(
            "https://v2ray2clash.netlify.app/.netlify/functions/clash",
            false,
            $context
        );

        // 设置响应头，强制下载为 .yaml 文件
        header("Content-Type: text/yaml; charset=UTF-8");
        header("Content-Disposition: attachment; filename=nodes.yaml");
        echo $content;
        exit;
    }
    
    response(200, $content, "Content-Type: text/plain; charset=UTF-8");
}

// load sub and scatter node list
$sub_list = load_file_to_array("sub.txt");
$scatter_nodes = load_file_to_array("scatter.txt");

// get sub node list
$sub_nodes = array();
foreach ($sub_list as $sub) {
    $sub_content = download_file($sub, 3);
    if (strpos($sub_content, "://") === false) {
        $sub_content = base64_decode($sub_content);
    }
    $sub_nodes = array_merge($sub_nodes, load_string_to_array($sub_content));
}

// merge sub nodes and scatter nodes
$nodes = array_merge($sub_nodes, $scatter_nodes);
$nodes = array_filter($nodes);
$nodes = array_unique($nodes);

// response
response_nodes($nodes);

?>