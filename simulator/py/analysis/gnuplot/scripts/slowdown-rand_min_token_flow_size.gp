
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html

set xlabel ''
set ylabel 'Mean Slowdown' font ",18"

set grid y
set key left top samplen 2 font ",12"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror font ",18"
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [-1:6]
set xtics 1
#set mxtics 1

set yrange [1:12]
set logscale y 2
f(x) = 2**x
set ytics ("1" f(0), "2" f(1), "4" f(2), "8" f(3))
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms
set style histogram errorbars gap 2 lw 1

set boxwidth 1.0 absolute
set style fill   pattern 7 border

set terminal eps enhanced
set output 'img/'.ARG1.'_rand_min_token_slowdown_size.eps'

plot 'data/'.ARG1.'_rand_min_token_slowdown_size.dat' using 2:3:xtic(1) title 't_{min}=1BDP' fillstyle pattern 1, \
	'' using 4:5 title 't_{min}=2BDP' fillstyle pattern 2, \
	'' using 6:7 title 't_{min}=3BDP' fillstyle pattern 3, \
	'' using 8:9 title 't_{min}=4BDP' fillstyle pattern 4, \
	'' using 10:11 title 't_{min}=5BDP' fillstyle pattern 5, \
	'' using 12:13 title 't_{min}=6BDP' fillstyle pattern 6, \
	'' using 14:15 title 't_{min}=7BDP' fillstyle pattern 7, \
	'' using 16:17 title 't_{min}=8BDP' fillstyle pattern 8, \
	'' using 18:19 title 't_{min}=9BDP' fillstyle pattern 9, \
