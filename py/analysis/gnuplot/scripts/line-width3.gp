
set xlabel 'Load'
set ylabel 'Utilization'

set grid
set key left top
#set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [1:5]
set xtics 1, .5, 5
set mxtics 1

set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 3
set style line 2 linecolor rgb '#008000' linetype 1 linewidth 3
set style line 3 linecolor rgb '#FFA500' linetype 1 linewidth 3
set style line 4 linecolor rgb '#FF6347	' linetype 1 linewidth 3

set terminal pdf enhanced
set output 'img/line-width3.pdf'
plot 'data/lines.dat' using 1:2 with lines linestyle 1 title 'pFabric',\
'' using 1:3 with lines linestyle 2 title 'Fastpass',\
'' using 1:4 with lines linestyle 3 title 'pHost',\
'' using 1:5 with lines linestyle 4 title 'Ranking'


# set terminal xterm
# replot
