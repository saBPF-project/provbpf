CORES="2"
CLIENTS="2 4 8 16 32"
pgbench -i -s 70 bench2
for c in $CLIENTS; do
	pgbench -T 30 -j $CORES -c $c bench2
done
