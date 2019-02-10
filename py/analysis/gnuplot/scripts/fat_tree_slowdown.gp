
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html

set xlabel ''
set ylabel 'Mean Slowdown' font ",18"

set grid y
set key right top samplen 2 font ",16"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror font ",18"
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

set terminal eps enhanced
set output "img/fat_tree_slowdown.eps"

plot "data/fat_tree_slowdown.dat" using 2:xtic(1) title 'pFabric' fillstyle pattern 1, \
	'' using 3 title 'pHost' fillstyle pattern 4 transparent lc rgb "#FF8000", \
	'' using 4 title 'RUF' fillstyle pattern 2 transparent lc rgb "#009900"