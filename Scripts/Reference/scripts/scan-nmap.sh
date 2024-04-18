root=20230324
for i in $(seq -f "%02g" 18 23)
do
#  echo $i
  thread=thread$i
  part=part$i.txt
#  echo $thread
#  echo $part
#  echo
  mkdir results-$root/$thread;
  while read -ra line; do 
    ip="${line[0]}"; port="${line[1]}";
    /usr/local/bin/nmap -Pn -n --script ssl-enum-ciphers -p $port $ip -oX results-$root/$thread/$ip-$port.xml | tee results-$root/$thread/$ip-$port.txt;
#    /usr/local/bin/nmap -Pn -n --script ssl-enum-ciphers -p $port $ip -oN threads-nmap/$thread/$ip-$port.txt;
    /usr/local/bin/nmap -Pn -n --script sslv2 -p $port $ip -oX results-$root/$thread/$ip-$port-sslv2.xml | tee results-$root/$thread/$ip-$port-sslv2.txt;
#    /usr/local/bin/nmap -Pn -n --script sslv2 -p $port $ip -oN threads-nmap/$thread/$ip-$port-sslv2.txt;
#    /usr/local/bin/nmap -Pn -n --script ssl-poodle -p $port $ip -oX threads-nmap/$thread/$ip-$port-poodle.xml;
#    /usr/local/bin/nmap -Pn -n --script ssl-poodle -p $port $ip -oN threads-nmap/$thread/$ip-$port-poodle.txt;
    /usr/local/bin/nmap -Pn -n --script ssl-heartbleed -p $port $ip -oX results-$root/$thread/$ip-$port-heartbleed.xml | tee results-$root/$thread/$ip-$port-heartbleed.txt;
#    /usr/local/bin/nmap -Pn -n --script ssl-heartbleed -p $port $ip -oN threads-nmap/$thread/$ip-$port-heartbleed.txt;
    /usr/local/bin/nmap -Pn -n --script ssl-dh-params -p $port $ip -oX results-$root/$thread/$ip-$port-dh-params.xml | tee results-$root/$thread/$ip-$port-dh-params.txt;
#    /usr/local/bin/nmap -Pn -n --script ssl-dh-params -p $port $ip -oN threads-nmap/$thread/$ip-$port-dh-params.txt;
   done < parts-$root/$part &
done
