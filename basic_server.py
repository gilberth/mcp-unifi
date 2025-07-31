#!/usr/bin/env python3
"""
Servidor MCP básico para UniFi
Ultra-básico para resolver problemas de timeout en Smithery
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class MCPUniFiHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Obtener parámetros de configuración de variables de entorno
        self.unifi_ip = os.environ.get('UNIFI_ROUTER_IP', '192.168.1.1')
        self.unifi_username = os.environ.get('UNIFI_USERNAME', 'admin')
        self.unifi_password = os.environ.get('UNIFI_PASSWORD', 'password')
        self.unifi_port = os.environ.get('UNIFI_PORT', '443')
        self.unifi_verify_ssl = os.environ.get('UNIFI_VERIFY_SSL', 'false').lower() == 'true'
        super().__init__(*args, **kwargs)
    def do_GET(self):
        """Maneja solicitudes GET - health check e información"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "service": "mcp-unifi-basic",
                "config": {
                    "unifi_ip": self.unifi_ip,
                    "unifi_port": self.unifi_port,
                    "unifi_username": self.unifi_username,
                    "ssl_verify": self.unifi_verify_ssl
                }
            }
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "name": "MCP UniFi Basic Server",
                "version": "1.0.0",
                "description": "Basic MCP server for UniFi network management",
                "endpoints": ["/health", "/mcp"]
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Maneja solicitudes POST - protocolo MCP"""
        if self.path == '/mcp':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode())
                response = self.handle_mcp_request(request_data)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_response = {"error": str(e)}
                self.wfile.write(json.dumps(error_response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        """Maneja solicitudes OPTIONS - CORS"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def handle_mcp_request(self, request_data):
        """Maneja solicitudes del protocolo MCP"""
        method = request_data.get('method', '')
        
        if method == 'initialize':
            return {
                "jsonrpc": "2.0",
                "id": request_data.get('id'),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "mcp-unifi-basic",
                        "version": "1.0.0"
                    }
                }
            }
        
        elif method == 'tools/list':
            return {
                "jsonrpc": "2.0",
                "id": request_data.get('id'),
                "result": {
                    "tools": [
                        {
                            "name": "get_unifi_status",
                            "description": f"Get UniFi controller status from {self.unifi_ip}:{self.unifi_port}",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "required": []
                            }
                        },
                        {
                            "name": "list_devices",
                            "description": "List all UniFi network devices",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "device_type": {
                                        "type": "string",
                                        "description": "Filter by device type (ap, switch, gateway)",
                                        "enum": ["ap", "switch", "gateway", "all"]
                                    }
                                },
                                "required": []
                            }
                        },
                        {
                            "name": "get_network_info",
                            "description": "Get network information and statistics",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "include_clients": {
                                        "type": "boolean",
                                        "description": "Include connected clients information"
                                    }
                                },
                                "required": []
                            }
                        }
                    ]
                }
            }
        
        elif method == 'tools/call':
            tool_name = request_data.get('params', {}).get('name', '')
            tool_args = request_data.get('params', {}).get('arguments', {})
            
            if tool_name == 'get_unifi_status':
                return {
                    "jsonrpc": "2.0",
                    "id": request_data.get('id'),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"UniFi Controller Status:\n- IP: {self.unifi_ip}:{self.unifi_port}\n- Username: {self.unifi_username}\n- SSL Verify: {self.unifi_verify_ssl}\n- Status: Connected (simulated)\n- Version: 7.5.176 (simulated)\n- Uptime: 5 days, 3 hours (simulated)"
                            }
                        ]
                    }
                }
            
            elif tool_name == 'list_devices':
                device_type = tool_args.get('device_type', 'all')
                return {
                    "jsonrpc": "2.0",
                    "id": request_data.get('id'),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"UniFi Devices (filter: {device_type}):\n1. Access Point - UAP-AC-PRO (Online)\n2. Switch - US-24-250W (Online)\n3. Gateway - UDM-Pro (Online)\n\nNote: This is simulated data. Real implementation would connect to {self.unifi_ip}:{self.unifi_port}"
                            }
                        ]
                    }
                }
            
            elif tool_name == 'get_network_info':
                include_clients = tool_args.get('include_clients', False)
                clients_info = "\n- Connected Clients: 15 devices" if include_clients else ""
                return {
                    "jsonrpc": "2.0",
                    "id": request_data.get('id'),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Network Information:\n- Controller: {self.unifi_ip}:{self.unifi_port}\n- Networks: 3 configured\n- Total Bandwidth: 1 Gbps{clients_info}\n\nNote: This is simulated data from basic server."
                            }
                        ]
                    }
                }
            
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_data.get('id'),
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found"
                    }
                }
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_data.get('id'),
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }

def main():
    port = int(os.environ.get('PORT', 3000))
    
    print(f"Starting MCP UniFi Basic Server on port {port}")
    print(f"UniFi Configuration:")
    print(f"  - IP: {os.environ.get('UNIFI_ROUTER_IP', '192.168.1.1')}")
    print(f"  - Port: {os.environ.get('UNIFI_PORT', '443')}")
    print(f"  - Username: {os.environ.get('UNIFI_USERNAME', 'admin')}")
    print(f"  - SSL Verify: {os.environ.get('UNIFI_VERIFY_SSL', 'false')}")
    
    server = HTTPServer(('0.0.0.0', port), MCPUniFiHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()

if __name__ == '__main__':
    main()