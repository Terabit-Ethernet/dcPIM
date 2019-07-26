
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,9" linewidth 4 rounded fontscale 1.0

set xlabel ''
set ylabel 'Mean Slowdown' font ",9"

set grid y
set key right top samplen 2 font ",9"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror font ",9"
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [-0.5:2.5]
set xtics 1
#set mxtics 1

set yrange [0:3]
# set ytics 5

set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 10 border

set output "img/fat_tree_slowdown.eps"

plot "data/fat_tree_slowdown.dat" using 2:xtic(1) title 'pFabric' fillstyle pattern 1, \
	'' using 3 title 'pHost' fillstyle pattern 4 transparent lc rgb "#FF8000", \
	'' using 4 title 'c-MP3' fillstyle pattern 6 transparent lc rgb "#009900", \
	'' using 5 title 'd-MP3' fillstyle pattern 2 transparent lc rgb "#003300"