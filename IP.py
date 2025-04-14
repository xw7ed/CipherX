import tkinter as tk
from tkinter import messagebox, simpledialog
import socket
import dns.resolver
import requests
import whois
from ipwhois import IPWhois
import ssl
import datetime

# وظائف الأدوات
def subdomain_finder():
    domain = simpledialog.askstring("Input", "Enter domain:")
    if not domain:
        return
    try:
        subdomains = ["www", "mail", "ftp", "test"]
        found = []
        for sub in subdomains:
            url = f"{sub}.{domain}"
            try:
                socket.gethostbyname(url)
                found.append(url)
            except:
                continue
        messagebox.showinfo("Result", "\n".join(found) if found else "No subdomains found.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def port_scanner():
    host = simpledialog.askstring("Input", "Enter host:")
    if not host:
        return
    open_ports = []
    for port in [21, 22, 23, 53, 80, 443, 8080]:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(str(port))
            sock.close()
        except:
            pass
    messagebox.showinfo("Result", f"Open Ports:\n{', '.join(open_ports)}")

def ip_to_host():
    ip = simpledialog.askstring("Input", "Enter IP:")
    try:
        host = socket.gethostbyaddr(ip)
        messagebox.showinfo("Result", host[0])
    except Exception as e:
        messagebox.showerror("Error", str(e))

def geo_ip():
    ip = simpledialog.askstring("Input", "Enter IP:")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        messagebox.showinfo("Geo IP", str(response))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def dns_lookup():
    domain = simpledialog.askstring("Input", "Enter domain:")
    try:
        result = socket.gethostbyname(domain)
        messagebox.showinfo("DNS Lookup", result)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def dns_records():
    domain = simpledialog.askstring("Input", "Enter domain:")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        records = "\n".join([r.to_text() for r in answers])
        messagebox.showinfo("DNS Records", records)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def reverse_dns():
    ip = simpledialog.askstring("Input", "Enter IP address:")
    try:
        host = socket.gethostbyaddr(ip)
        messagebox.showinfo("Reverse DNS", host[0])
    except Exception as e:
        messagebox.showerror("Error", str(e))

def whois_lookup():
    domain = simpledialog.askstring("Input", "Enter domain:")
    try:
        w = whois.whois(domain)
        messagebox.showinfo("Whois", str(w))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def shodan_scanner():
    api_key = simpledialog.askstring("Shodan API Key", "Enter your Shodan API key:")
    if not api_key:
        return
    import shodan
    try:
        api = shodan.Shodan(api_key)
        query = simpledialog.askstring("Search", "Enter Shodan search query:")
        results = api.search(query)
        msg = f"Results found: {results['total']}\n\n"
        for r in results['matches'][:5]:
            msg += f"IP: {r['ip_str']}, Port: {r['port']}\n"
        messagebox.showinfo("Shodan", msg)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def email_breach_check():
    email = simpledialog.askstring("Input", "Enter email:")
    try:
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={
            "hibp-api-key": "YOUR_API_KEY",  # لازم تستبدلها بمفتاحك
            "User-Agent": "CyberToolkit"
        })
        if response.status_code == 200:
            data = response.json()
            breaches = "\n".join([b['Name'] for b in data])
            messagebox.showinfo("Email Leaks Found", breaches)
        elif response.status_code == 404:
            messagebox.showinfo("Good News", "No breaches found.")
        else:
            messagebox.showerror("Error", f"Status code: {response.status_code}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def ssl_checker():
    domain = simpledialog.askstring("Input", "Enter domain:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                messagebox.showinfo("SSL Info", f"SSL expires on: {exp_date}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def not_ready(name):
    messagebox.showinfo("Coming Soon", f"{name} will be added soon!")

# واجهة المستخدم
root = tk.Tk()
root.title("Cyber Toolkit")
root.geometry("450x800")
root.configure(bg="#1e1e1e")

tk.Label(root, text="Choose a tool:", fg="white", bg="#1e1e1e", font=("Arial", 14)).pack(pady=10)

tools = [
    ("🔍 Subdomain Finder", subdomain_finder),
    ("🔌 Port Scanner", port_scanner),
    ("🏠 IP to Host", ip_to_host),
    ("📍 Geo IP", geo_ip),
    ("🔗 DNS Lookup", dns_lookup),
    ("📝 DNS Records", dns_records),
    ("🔁 Reverse DNS", reverse_dns),
    ("📃 Whois Lookup", whois_lookup),
    ("🛰️ Shodan Scanner", shodan_scanner),
    ("🔓 Email Breach Check", email_breach_check),
    ("🔐 SSL Checker", ssl_checker),
    ("❓ Help", lambda: messagebox.showinfo("Help", "By w7ed – Cybersecurity Toolkit"))
]

for label, action in tools:
    btn = tk.Button(root, text=label, command=action, font=("Arial", 12),
                    bg="#333", fg="white", width=30, height=2)
    btn.pack(pady=5)

root.mainloop()
