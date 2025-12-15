<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Packet Sniffer - README</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #24292e;
            background: #ffffff;
            padding: 40px 20px;
        }
        
        .container {
            max-width: 980px;
            margin: 0 auto;
        }
        
        h1 {
            font-size: 2.5em;
            border-bottom: 1px solid #e1e4e8;
            padding-bottom: 0.3em;
            margin-bottom: 16px;
            font-weight: 600;
        }
        
        h2 {
            font-size: 1.75em;
            border-bottom: 1px solid #e1e4e8;
            padding-bottom: 0.3em;
            margin-top: 24px;
            margin-bottom: 16px;
            font-weight: 600;
        }
        
        h3 {
            font-size: 1.25em;
            margin-top: 24px;
            margin-bottom: 16px;
            font-weight: 600;
        }
        
        p {
            margin-bottom: 16px;
        }
        
        .badge-container {
            margin: 20px 0;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            margin-right: 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-portable {
            background: #28a745;
            color: white;
        }
        
        .badge-size {
            background: #0366d6;
            color: white;
        }
        
        .badge-windows {
            background: #6f42c1;
            color: white;
        }
        
        .screenshot-placeholder {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: 2px dashed #0366d6;
            border-radius: 8px;
            padding: 80px 40px;
            text-align: center;
            margin: 30px 0;
            color: white;
            font-size: 1.2em;
            font-weight: 600;
        }
        
        .screenshot-placeholder small {
            display: block;
            margin-top: 10px;
            font-size: 0.8em;
            opacity: 0.9;
        }
        
        ul, ol {
            margin-left: 2em;
            margin-bottom: 16px;
        }
        
        li {
            margin-bottom: 8px;
        }
        
        code {
            background: #f6f8fa;
            padding: 3px 6px;
            border-radius: 3px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.9em;
        }
        
        pre {
            background: #f6f8fa;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            margin-bottom: 16px;
        }
        
        pre code {
            background: none;
            padding: 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 16px;
            border: 1px solid #d0d7de;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #d0d7de;
        }
        
        th {
            background: #f6f8fa;
            font-weight: 600;
        }
        
        tr:nth-child(even) {
            background: #f6f8fa;
        }
        
        .highlight-box {
            background: #fff5b1;
            border-left: 4px solid #ffd700;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .note-box {
            background: #e1f5fe;
            border-left: 4px solid #0366d6;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ff9800;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        footer {
            text-align: center;
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #e1e4e8;
            color: #586069;
            font-style: italic;
        }
        
        strong {
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Packet Sniffer</h1>
        
        <div class="badge-container">
            <span class="badge badge-portable">PORTABLE</span>
            <span class="badge badge-size">13MB</span>
            <span class="badge badge-windows">WINDOWS</span>
        </div>
        
        <p>A network traffic analyzer that captures and displays packets in real-time. It's basically tcpdump for Windows but with a visual interface. Small, portable, and doesn't need installation - just 13MB total.</p>
        
        <div class="screenshot-placeholder">
            SCREENSHOT GOES HERE
            <small>Replace this section with your actual screenshot</small>
            <small>Recommended: PNG format, around 1200x800px</small>
        </div>
        
        <h2>What it does</h2>
        <p>Monitor network traffic on your Windows machine. Filter by IP addresses, protocols, and ports. Watch packets in real-time as they pass through your network. Save everything to PCAP files that you can open in Wireshark later.</p>
        
        <p>If you've used tcpdump on Linux, this is similar but with an interface that's easier to work with.</p>
        
        <h2>Features</h2>
        
        <ul>
            <li>Real-time packet capture and display</li>
            <li>Filter by source/destination IP, protocol (TCP/UDP/ICMP), and port</li>
            <li>TCP flag monitoring - see SYN, ACK, FIN, RST packets</li>
            <li>Payload preview showing first 30 bytes</li>
            <li>Export to PCAP format</li>
            <li>Clean terminal interface with color coding</li>
            <li>Automatic file naming so you don't overwrite old captures</li>
            <li>Completely portable - runs from USB drive</li>
            <li>Only 13MB total size</li>
            <li>No registry changes or system modifications</li>
        </ul>
        
        <h2>Requirements</h2>
        <ul>
            <li>Windows (uses WinDivert driver)</li>
            <li>Python 3.7 or newer</li>
            <li>Administrator privileges - needed for packet capture</li>
        </ul>
        
        <h2>Installation</h2>
        
        <p>Install the required packages:</p>
        <pre><code>pip install pydivert textual</code></pre>
        
        <p>You also need the WinDivert driver. Put <code>WinDivert64.dll</code> (or <code>WinDivert.dll</code> for 32-bit) in either:</p>
        <ul>
            <li>A <code>pydivert</code> subfolder next to the script</li>
            <li>The same directory as the script</li>
        </ul>
        
        <h2>Usage</h2>
        
        <p>Run with administrator privileges:</p>
        <pre><code>python sniffer.py</code></pre>
        
        <h3>Interface Controls</h3>
        
        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>IP SRC</strong></td>
                    <td>Filter by source IP - choose from your local IPs or type a custom one</td>
                </tr>
                <tr>
                    <td><strong>PROTO</strong></td>
                    <td>Select protocol - TCP, UDP, ICMP, or any</td>
                </tr>
                <tr>
                    <td><strong>IP DST</strong></td>
                    <td>Filter by destination IP address</td>
                </tr>
                <tr>
                    <td><strong>PORT</strong></td>
                    <td>Filter by specific port number</td>
                </tr>
                <tr>
                    <td><strong>ENABLE SAVE PCAP</strong></td>
                    <td>Toggle saving to file</td>
                </tr>
                <tr>
                    <td><strong>FILENAME</strong></td>
                    <td>Choose output filename - auto-generates if you leave it empty</td>
                </tr>
            </tbody>
        </table>
        
        <p>Click START SNIFFER to begin, STOP SNIFFER to halt.</p>
        
        <h3>Filter Examples</h3>
        
        <table>
            <thead>
                <tr>
                    <th>What you want</th>
                    <th>How to set it up</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Monitor all traffic from your machine</td>
                    <td>Select your local IP in IP SRC</td>
                </tr>
                <tr>
                    <td>Capture HTTP traffic</td>
                    <td>Set PROTO to TCP, PORT to 80</td>
                </tr>
                <tr>
                    <td>Watch DNS queries</td>
                    <td>Set PROTO to UDP, PORT to 53</td>
                </tr>
                <tr>
                    <td>Track traffic to a specific server</td>
                    <td>Enter the IP in IP DST field</td>
                </tr>
                <tr>
                    <td>Monitor HTTPS connections</td>
                    <td>Set PROTO to TCP, PORT to 443</td>
                </tr>
                <tr>
                    <td>Capture SSH traffic</td>
                    <td>Set PROTO to TCP, PORT to 22</td>
                </tr>
            </tbody>
        </table>
        
        <h2>Output Format</h2>
        
        <p>The packet table shows:</p>
        
        <table>
            <thead>
                <tr>
                    <th>Column</th>
                    <th>What it means</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>TIME</strong></td>
                    <td>When the packet was captured</td>
                </tr>
                <tr>
                    <td><strong>PROTO</strong></td>
                    <td>Protocol type - TCP, UDP, or ICMP</td>
                </tr>
                <tr>
                    <td><strong>SRC</strong></td>
                    <td>Source IP and port</td>
                </tr>
                <tr>
                    <td><strong>DST</strong></td>
                    <td>Destination IP and port</td>
                </tr>
                <tr>
                    <td><strong>FLAGS</strong></td>
                    <td>TCP flags if applicable</td>
                </tr>
                <tr>
                    <td><strong>TTL</strong></td>
                    <td>Time to live value</td>
                </tr>
                <tr>
                    <td><strong>LEN</strong></td>
                    <td>Packet length in bytes</td>
                </tr>
                <tr>
                    <td><strong>PAYLOAD</strong></td>
                    <td>First 30 bytes of payload - only printable characters shown</td>
                </tr>
            </tbody>
        </table>
        
        <h2>Why it's portable</h2>
        
        <div class="highlight-box">
            <p>This tool is designed to be fully portable:</p>
            <ul>
                <li>Copy the folder to a USB drive</li>
                <li>Run from any Windows machine that you have admin rights on</li>
                <li>No registry modifications</li>
                <li>No system-wide installation needed</li>
                <li>All dependencies bundled in 13MB</li>
            </ul>
            <p>Good for network admins who need a diagnostic tool they can carry around.</p>
        </div>
        
        <h2>Comparison with tcpdump</h2>
        
        <table>
            <thead>
                <tr>
                    <th>Feature</th>
                    <th>tcpdump (Linux)</th>
                    <th>This Tool (Windows)</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Platform</td>
                    <td>Linux/Unix</td>
                    <td>Windows</td>
                </tr>
                <tr>
                    <td>Interface</td>
                    <td>Command line</td>
                    <td>Terminal UI</td>
                </tr>
                <tr>
                    <td>Size</td>
                    <td>Around 1MB</td>
                    <td>Around 13MB</td>
                </tr>
                <tr>
                    <td>Filtering</td>
                    <td>Command line arguments</td>
                    <td>Visual dropdown menus</td>
                </tr>
                <tr>
                    <td>Output</td>
                    <td>PCAP files</td>
                    <td>Live view plus PCAP files</td>
                </tr>
                <tr>
                    <td>Learning curve</td>
                    <td>Steep</td>
                    <td>Gentle</td>
                </tr>
            </tbody>
        </table>
        
        <h2>Important notes</h2>
        
        <div class="note-box">
            <ul>
                <li>You need admin/elevated privileges to access the network driver</li>
                <li>Large capture sessions might slow things down</li>
                <li>PCAP files work with Wireshark and similar tools</li>
                <li>The tool uses sniff mode so it won't mess with your normal traffic</li>
                <li>Good for quick network diagnostics without installing heavy tools</li>
            </ul>
        </div>
        
        <h2>Troubleshooting</h2>
        
        <div class="warning-box">
            <p><strong>Driver error on startup:</strong> Make sure you're running as administrator and the WinDivert DLL is in the right location.</p>
        </div>
        
        <p><strong>No packets showing up:</strong> Check your filter settings. Try "ANY IP" and "ANY PROTO" first to make sure capture is working.</p>
        
        <p><strong>Can't save file:</strong> Check that you have write permissions in the script directory.</p>
        
        <p><strong>Running slow:</strong> Reduce your filter scope or turn off PCAP saving for better speed.</p>
        
       
        
        <h2>License</h2>
        
        <p>This is a network monitoring tool for educational purposes and legitimate network administration. Make sure you have permission to monitor network traffic before using it.</p>
        
        <footer>
            <p>A portable tcpdump alternative for Windows</p>
        </footer>
    </div>
</body>
</html>
