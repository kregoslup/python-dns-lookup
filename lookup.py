import socket
import random
import struct
import sys


def dns_question(header, query, dnserver):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dnserver, 53))
    except socket.error as error:
        sys.stderr.write("Error: Could not connect to server (%s)" % error.strerror)
        return None
    send_question(s, pack_question(header, query))
    data = s.recv(1024)
    print(data)
    s.close()


def pack_question(header, question):
    return header + question.question_bits


def send_question(s, bits):
    packet_len = struct.pack(">H", len(bits))
    s.sendall(packet_len)
    s.sendall(bits)


class DNSHeader:
    def __init__(self):
        self.header_id = random.getrandbits(16)
        self.qr_flag = self.opcode = self.authoritative_answer\
            = self.truncation_flag = self.recursion_available\
            = self.z_flag = self.rcode = self.an_count = self.ns_count\
            = self.ar_count = 0
        self.recursion_desired = self.qd_count = 1
        self.header_bits = ()

    def prepare_dns_question_header(self):
        self.header_bits = (self.rcode |
                            self.z_flag << 4 |
                            self.recursion_available << 7 |
                            self.recursion_desired << 8 |
                            self.truncation_flag << 9 |
                            self.authoritative_answer << 10 |
                            self.opcode << 11 |
                            self.qr_flag << 15)

    def pack_dns_header(self):
        header = struct.pack(">H", self.header_id)
        header = header + struct.pack(">H", self.header_bits)
        header = header + struct.pack(">HHHH", self.qd_count, self.an_count,
                                      self.ns_count, self.ar_count)
        return header


class DNSQuestion:
    def __init__(self):
        self.qname = []
        self.qtype = None
        self.qtype_bits = []
        self.qclass = 1
        self.question_bits = bytes()

    def preparing_question_bits(self, domain, question_type):
        for domain_part in domain.split('.'):
            self.qname.append(struct.pack(">B", len(domain_part)))
            self.question_bits = self.question_bits + struct.pack(">B", len(domain_part))
            self.qname.append(domain_part)
            self.question_bits = self.question_bits + str.encode(domain_part)
        self.qname.append("\0")
        self.question_bits = self.question_bits + b'\0'

        if question_type == 'A':
            self.qtype = 1
        elif question_type == 'MX':
            self.qtype = 15
        elif question_type == "NS":
            self.qtype = 2
        self.qtype_bits.append(struct.pack(">HH", self.qtype, self.qclass))
        self.question_bits = self.question_bits + struct.pack(">HH", self.qtype, self.qclass)


if __name__ == '__main__':
    h = DNSHeader()
    q = DNSQuestion()
    h.prepare_dns_question_header()
    h.pack_dns_header()
    q.preparing_question_bits("hekko.pl", "A")
    dns_question(h.pack_dns_header(), q, '8.8.8.8')