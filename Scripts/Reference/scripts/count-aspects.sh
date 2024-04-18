#!/bin/bash
#
# Takes a score file as argument, then returns count for various SSL, TLS, cipher parameters
#
echo
echo "Working with results file: $1"
echo "-------------------------------------------------------------"
echo -n "Total lines: "
result=$(wc -l $1)
echo "$result"
echo -n "Port 443 services: "
result=$(grep ",443," "$1" | wc -l)
echo "$result"
echo -n "nonStd port services: "
result=$(grep -v ",443," $1 | wc -l)
echo "$result"
echo

echo -n "SSLv2 total: "
result=$(grep "SSLv2" "$1" | wc -l)
echo -n "$result  "
echo -n "SSLv2 port 443: "
result=$(grep ",443," "$1" | grep "SSLv2" | wc -l)
echo -n "$result  "
echo -n "SSLv2 nonStd port: "
result=$(grep -v ",443," "$1" | grep "SSLv2" | wc -l)
echo "$result"
echo

echo -n "SSLv3 total: "
result=$(grep "SSLv3" "$1" | wc -l)
echo -n "$result  "
echo -n "SSLv3 port 443: "
result=$(grep ",443," "$1" | grep "SSLv3" | wc -l)
echo -n "$result  "
echo -n "SSLv3 nonStd port: "
result=$(grep -v ",443," "$1" | grep "SSLv3" | wc -l)
echo "$result"
echo

echo -n "TLSv1.0 total: "
result=$(grep "TLSv1\.0" "$1" | wc -l)
echo -n "$result  "
echo -n "TLSv1.0 port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.0" | wc -l)
echo -n "$result  "
echo -n "TLSv1.0 nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.0" | wc -l)
echo "$result"
echo

echo -n "TLSv1.1 total: "
result=$(grep "TLSv1\.1" "$1" | wc -l)
echo -n "$result  "
echo -n "TLSv1.1 port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.1" | wc -l)
echo -n "$result  "
echo -n "TLSv1.1 nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.1" | wc -l)
echo "$result"
echo

echo -n "TLSv1.2 total: "
result=$(grep "TLSv1\.2" "$1" | wc -l)
echo -n "$result  "
echo -n "TLSv1.2 port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.2" | wc -l)
echo -n "$result  "
echo -n "TLSv1.2 nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.2" | wc -l)
echo "$result"
echo

echo -n "TLSv1.3 total: "
result=$(grep "TLSv1\.3" "$1" | wc -l)
echo -n "$result  "
echo -n "TLSv1.3 port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.3" | wc -l)
echo -n "$result  "
echo -n "TLSv1.3 nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.3" | wc -l)
echo "$result"
echo

echo -n "DHE or AKE total: "
result=$(grep "DHE\|AKE" "$1" | wc -l)
echo -n "$result  "
echo -n "DHE or AKE port 443: "
result=$(grep ",443," "$1" | grep "DHE\|AKE" | wc -l)
echo -n "$result  "
echo -n "DHE or AKE nonStd port: "
result=$(grep -v ",443," "$1" | grep "DHE\|AKE" | wc -l)
echo "$result"
echo

echo -n "DHE or AKE only total: "
result=$(grep "DHE\|AKE" "$1" | grep -v "PFS" | wc -l)
echo -n "$result  "
echo -n "DHE or AKE only port 443: "
result=$(grep ",443," "$1" | grep "DHE\|AKE" | grep -v "PFS" | wc -l)
echo -n "$result  "
echo -n "DHE or AKE only nonStd port: "
result=$(grep -v ",443," "$1" | grep "DHE\|AKE" | grep -v "PFS" | wc -l)
echo "$result"
echo

echo -n "EXPORT total: "
result=$(grep "EXPORT" "$1" | wc -l)
echo -n "$result  "
echo -n "EXPORT port 443: "
result=$(grep ",443," "$1" | grep "EXPORT" | wc -l)
echo -n "$result  "
echo -n "EXPORT nonStd port: "
result=$(grep -v ",443," "$1" | grep "EXPORT" | wc -l)
echo "$result"
echo

echo -n "DES total: "
result=$(grep "[,;]DES" "$1" | wc -l)
echo -n "$result  "
echo -n "DES port 443: "
result=$(grep ",443," "$1" | grep "[,;]DES" | wc -l)
echo -n "$result  "
echo -n "DES nonStd port: "
result=$(grep -v ",443," "$1" | grep "[,;]DES" | wc -l)
echo "$result"

echo -n "3DES total: "
result=$(grep "3DES" "$1" | wc -l)
echo -n "$result  "
echo -n "3DES port 443: "
result=$(grep ",443," "$1" | grep "3DES" | wc -l)
echo -n "$result  "
echo -n "3DES nonStd port: "
result=$(grep -v ",443," "$1" | grep "3DES" | wc -l)
echo "$result"
echo

echo -n "MD5 total: "
result=$(grep "MD5" "$1" | wc -l)
echo -n "$result  "
echo -n "MD5 port 443: "
result=$(grep ",443," "$1" | grep "MD5" | wc -l)
echo -n "$result  "
echo -n "MD5 nonStd port: "
result=$(grep -v ",443," "$1" | grep "MD5" | wc -l)
echo "$result"
echo

echo -n "Heartbleed total: "
result=$(grep -i "Heartbleed" "$1" | wc -l)
echo -n "$result  "
echo -n "Heartbleed port 443: "
result=$(grep ",443," "$1" | grep -i "Heartbleed" | wc -l)
echo -n "$result  "
echo -n "Heartbleed nonStd port: "
result=$(grep -v ",443," "$1" | grep -i "Heartbleed" | wc -l)
echo "$result"
echo

echo -n "Compression total: "
result=$(grep -i "Compress" "$1" | wc -l)
echo -n "$result  "
echo -n "Compression port 443: "
result=$(grep ",443," "$1" | grep -i "Compress" | wc -l)
echo -n "$result  "
echo -n "Compression nonStd port: "
result=$(grep -v ",443," "$1" | grep -i "Compress" | wc -l)
echo "$result"
echo

echo -n "TLS1.{23} and not TLS1.{01} only total: "
result=$(grep "TLSv1\.[23]" "$1" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo -n "$result  "
echo -n "TLS1.{23} and not TLS1.{01} only port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.[23]" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo -n "$result  "
echo -n "TLS1.{23} and not TLS1.{01} only nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.[23]" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo "$result"
echo

echo -n "RC4 total: "
result=$(grep "RC4" "$1" | wc -l)
echo -n "$result  "
echo -n "RC4 port 443: "
result=$(grep ",443," "$1" | grep "RC4" | wc -l)
echo -n "$result  "
echo -n "RC4 nonStd port: "
result=$(grep -v ",443," "$1" | grep "RC4" | wc -l)
echo "$result"
echo

echo -n "CBC total: "
result=$(grep "CBC" "$1" | wc -l)
echo -n "$result  "
echo -n "CBC port 443: "
result=$(grep ",443," "$1" | grep "CBC" | wc -l)
echo -n "$result  "
echo -n "CBC nonStd port: "
result=$(grep -v ",443," "$1" | grep "CBC" | wc -l)
echo "$result"
echo

echo -n "TLS1.{23} and not CBC total: "
result=$(grep "TLSv1\.[23]" "$1" | grep -v "CBC" | wc -l)
echo -n "$result  "
echo -n "TLS1.{23} and not CBC port 443: "
result=$(grep ",443," "$1" | grep "TLSv1\.[23]" | grep -v "CBC" | wc -l)
echo -n "$result  "
echo -n "TLS1.{23} and not CBC nonStd port: "
result=$(grep -v ",443," "$1" | grep "TLSv1\.[23]" | grep -v "CBC" | wc -l)
echo "$result"
echo

echo -n "Weak DH total: "
result=$(grep "Weak DH" "$1" | wc -l)
echo -n "$result  "
echo -n "Weak DH port 443: "
result=$(grep ",443," "$1" | grep "Weak DH" | wc -l)
echo -n "$result  "
echo -n "Weak DH nonStd port: "
result=$(grep -v ",443," "$1" | grep "Weak DH" | wc -l)
echo "$result"
echo

echo
echo "-------------------------------------------------------------"
echo

echo "SSL and TLS values for all ports (SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3):"
result=$(grep "SSLv2" "$1" | wc -l)
echo "$result"
result=$(grep "SSLv3" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.0" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.1" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.2" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.3" "$1" | wc -l)
echo "$result"
echo "Other parameters for all ports:"
result=$(grep "DHE\|AKE" "$1" | wc -l)
echo "$result"
result=$(grep "DHE\|AKE" "$1" | grep -v "PFS" | wc -l)
echo "$result"
echo
result=$(grep "EXPORT" "$1" | wc -l)
echo "$result"
result=$(grep "[,;]DES" "$1" | wc -l)
echo "$result"
result=$(grep "3DES" "$1" | wc -l)
echo "$result"
result=$(grep "MD5" "$1" | wc -l)
echo "$result"
result=$(grep -i "Heartbleed" "$1" | wc -l)
echo "$result"
result=$(grep -i "Compress" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.[23]" "$1" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo "$result"
result=$(grep "RC4" "$1" | wc -l)
echo "$result"
result=$(grep "CBC" "$1" | wc -l)
echo "$result"
result=$(grep "TLSv1\.[23]" "$1" | grep -v "CBC" | wc -l)
echo "$result"
result=$(grep "Weak DH" "$1" | wc -l)
echo "$result"
echo

echo "SSL and TLS values for port 443 (SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3):"
result=$(grep ",443," "$1" | grep "SSLv2" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "SSLv3" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.0" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.1" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.2" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.3" | wc -l)
echo "$result"
echo "Other parameters for all ports:"
result=$(grep ",443," "$1" | grep "DHE\|AKE" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "DHE\|AKE" | grep -v "PFS" | wc -l)
echo "$result"
echo
result=$(grep ",443," "$1" | grep "EXPORT" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "[,;]DES" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "3DES" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "MD5" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep -i "Heartbleed" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep -i "Compress" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.[23]" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "RC4" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "CBC" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "TLSv1\.[23]" | grep -v "CBC" | wc -l)
echo "$result"
result=$(grep ",443," "$1" | grep "Weak DH" | wc -l)
echo "$result"
echo

echo "SSL and TLS values for non-port 443 (SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3):"
result=$(grep -v ",443," "$1" | grep "SSLv2" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "SSLv3" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.0" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.1" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.2" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.3" | wc -l)
echo "$result"
echo "Other parameters for all ports:"
result=$(grep -v ",443," "$1" | grep "DHE\|AKE" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "DHE\|AKE" | grep -v "PFS" | wc -l)
echo "$result"
echo
result=$(grep -v ",443," "$1" | grep "EXPORT" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "[,;]DES" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "3DES" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "MD5" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep -i "Heartbleed" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep -i "Compress" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.[23]" | grep -v "TLSv1\.0" | grep -v "TLSv1\.1" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "RC4" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "CBC" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "TLSv1\.[23]" | grep -v "CBC" | wc -l)
echo "$result"
result=$(grep -v ",443," "$1" | grep "Weak DH" | wc -l)
echo "$result"
echo
