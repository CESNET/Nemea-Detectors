#examples of usage
#ip/prefix
#15.100.0.0/16    #comment
#8.8.8.0/24
#
#ip/prefix/port,port,port-port,port
#1.1.1.1/25
#2.1.1.1/22/10,
#3.1.1.1/13/80,53,100-200,50-120
#59.160.229.25/8/0-65000
#0.0.0.0/0/3333
#
# direction:
# "src", "dst" or "" (no keyword = src and dst)

dst 192.30.252.128/30/22 #github 
dst 131.103.20.160/28/22 #bitbucket

src 166.88.20.3/32   # valid communication to 195.113.184.18
src 195.113.44.19/32 # valid(???) communication to 88.208.125.10 & 88.208.125.11









