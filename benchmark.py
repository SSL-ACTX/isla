#!/usr/bin/env python3
# benchmark.py - Isla Stress Tester

import socket
import time
import threading
import argparse
import sys

# Global Counters
successful_reqs = 0
failed_reqs = 0
running = True


def load_worker(target_ip, target_port):
    global successful_reqs, failed_reqs, running

    while running:
        try:
            # Full TCP Connection -> Request -> Response -> Close
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target_ip, target_port))

            # Send HTTP Request to trigger the "Connection: close" logic in stack
            s.sendall(b"GET / HTTP/1.1\r\nHost: benchmark\r\n\r\n")

            # Read until close
            while True:
                data = s.recv(4096)
                if not data:
                    break

            s.close()
            successful_reqs += 1
        except:
            failed_reqs += 1


def run_benchmark(ip, port, threads, duration):
    global running, successful_reqs, failed_reqs

    print(f"[*] Benchmarking Isla at {ip}:{port}")
    print(f"[*] Threads: {threads} | Duration: {duration}s")
    print("-" * 50)
    print(
        f"{'Time':<10} | {'CPS (Conn/sec)':<15} | {'Total Success':<15} | {'Errors':<10}"
    )
    print("-" * 50)

    # Spawn Workers
    worker_threads = []
    for _ in range(threads):
        t = threading.Thread(target=load_worker, args=(ip, port))
        t.daemon = True
        t.start()
        worker_threads.append(t)

    start_time = time.time()
    last_check = start_time
    last_count = 0

    try:
        while time.time() - start_time < duration:
            time.sleep(1.0)
            current_time = time.time()
            elapsed = current_time - last_check

            # Calculate instantaneous CPS
            current_count = successful_reqs
            delta = current_count - last_count
            cps = delta / elapsed

            print(
                f"{int(current_time - start_time):<10} | {cps:<15.1f} | {current_count:<15} | {failed_reqs:<10}"
            )

            last_count = current_count
            last_check = current_time

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    running = False
    print("-" * 50)
    total_time = time.time() - start_time
    print(f"[*] Final Score: {successful_reqs / total_time:.2f} Connections/Sec")
    print(f"[*] Total Transferred: {successful_reqs} requests")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="192.168.1.2")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--time", type=int, default=30)
    args = parser.parse_args()

    run_benchmark(args.ip, args.port, args.threads, args.time)
