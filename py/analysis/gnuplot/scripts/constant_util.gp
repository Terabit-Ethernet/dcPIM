
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html

set xlabel ''
set ylabel 'Utilization'

set grid y
#set key left top
set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [-1:1]
set xtics 1
#set mxtics 1

set yrange [0:1]
# set ytics 5

set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 7 border

set terminal png enhanced
set output 'img/constant_util.png'
plot 'data/constant_util.dat' using 2:xtic(1) title 'pFabric' fillstyle pattern 1, \
	'' using 3 title 'Fastpass' fillstyle pattern 2, \
	'' using 4 title 'pHost' fillstyle pattern 4, \
	'' using 5 title 'Ruf' fillstyle pattern 5