#!/bin/bash

SCRIPTDIR=$(dirname ${0})
TARGETDIR="${SCRIPTDIR}/../target"

awk '
{
    for (i=1; i<=NF; i++)  {
        a[NR,i] = $i
    }
}
NF>p { p = NF }
END {
    for(j=1; j<=p; j++) {
        str=a[1,j]
        for(i=2; i<=NR; i++){
            str=str" "a[i,j];
        }
        print str
    }
}' ${TARGETDIR}/memory-in-samples.txt > ${TARGETDIR}/memory-in-samples-transposed.txt

awk '                            
{
    for (i=1; i<=NF; i++)  {
        a[NR,i] = $i
    }
}
NF>p { p = NF }
END {
    for(j=1; j<=p; j++) {
        str=a[1,j]
        for(i=2; i<=NR; i++){
            str=str" "a[i,j];
        }
        print str
    }
}' ${TARGETDIR}/memory-out-samples.txt > ${TARGETDIR}/memory-out-samples-transposed.txt


export GDFONTPATH=/usr/share/fonts/corefonts

gnuplot << EOF

set term png size 800,400
set key left top
set xlabel "Number of XML start elements"
#echo 'set xdata time';
set ylabel "Time [s]"
#echo 'set ytics (0,1)';
#echo 'set xrange ["01.12.2009":]';
#echo 'set timefmt "%s"';
#echo 'set format x "%d.%m.%Y"';
set style data linespoints
#echo 'set yrange [-0.25:1.25]';

set output "${TARGETDIR}/timing-inbound.png"
set title "Timing inbound (Timestamp Signature Encrypt)"
plot "${TARGETDIR}/timing-in-samples.txt" using 1:3 title 'swssf', \
     "${TARGETDIR}/timing-in-samples.txt" using 1:4 title 'swssf-compressed', \
     "${TARGETDIR}/timing-in-samples.txt" using 1:2 title 'WSS4J'

set output "${TARGETDIR}/timing-outbound.png"
set title "Timing outbound (Timestamp Signature Encrypt)"
plot "${TARGETDIR}/timing-out-samples.txt" using 1:3 title 'swssf', \
     "${TARGETDIR}/timing-out-samples.txt" using 1:4 title 'swssf-compressed', \
     "${TARGETDIR}/timing-out-samples.txt" using 1:2 title 'WSS4J'

set ylabel "Memory [MB]"

set output "${TARGETDIR}/memory-inbound.png"
set title "HEAP memory consumption inbound (Timestamp Signature Encrypt)"
plot "${TARGETDIR}/memory-in-samples-transposed.txt" using 1:4 title 'swssf', \
     "${TARGETDIR}/memory-in-samples-transposed.txt" using 1:3 title 'swssf-compressed', \
     "${TARGETDIR}/memory-in-samples-transposed.txt" using 1:2 title 'WSS4J'

set output "${TARGETDIR}/memory-outbound.png"
set title "HEAP memory consumption outbound (Timestamp Signature Encrypt)"
plot "${TARGETDIR}/memory-out-samples-transposed.txt" using 1:4 title 'swssf', \
     "${TARGETDIR}/memory-out-samples-transposed.txt" using 1:3 title 'swssf-compressed', \
     "${TARGETDIR}/memory-out-samples-transposed.txt" using 1:2 title 'WSS4J'
EOF
