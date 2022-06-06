
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

set yrange [1:50]
#set logscale y
f(x) = 2**x
#set ytics ("1" f(0), "2" f(1), "4" f(2), "8" f(3), "16" f(4), "infi" f(5))
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms
set style histogram errorbars gap 2 lw 1

set boxwidth 1.0 absolute
set style fill   pattern 7 border

set terminal eps enhanced
set output 'img/pim_k_'.ARG1.'_slowdown_size.eps'

plot 'data/pim_k_'.ARG1.'_slowdown_size.dat' using 2:3:xtic(1) title 'k=1' fillstyle pattern 1, \
	'' using 4:5 title 'k=2' fillstyle pattern 2, \
	'' using 6:7 title 'k=3' fillstyle pattern 3, \
	'' using 8:9 title 'k=4' fillstyle pattern 4, \
	'' using 10:11 title 'k=5' fillstyle pattern 5, \
	'' using 12:13 title 'k=6' fillstyle pattern 6, \
	'' using 14:15 title 'k=7' fillstyle pattern 7, \
	'' using 16:17 title 'k=8' fillstyle pattern 8, \
	'' using 18:19 title 'k=9' fillstyle pattern 9, \
 	'' using 20:21 title 'k=10' fillstyle pattern 10
