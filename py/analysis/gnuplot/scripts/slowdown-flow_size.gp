
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,7" linewidth 4 rounded fontscale 1.0

set xlabel 'Flow Size < {/Symbol a} BDP' font ",9"
set ylabel 'Mean Slowdown' font ",9"


#set key outside horizontal bottom center samplen 3 font ",9"

# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81

set border 3 back linestyle 80 


#set key top right horizontal noreverse enhanced autotitle box dashtype solid



unset key


set xrange [-1:6]
#set mxtics 1

set yrange [0:6]
#set logscale y 2
#f(x) = 2**x
#set ytics ("1" f(0), "2" f(1), "4" f(2), "8" f(3))
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms
set style histogram errorbars gap 2 lw 1

set boxwidth 1.0 absolute
set style fill   pattern 7 border

set output 'img/'.ARG1.'_'.ARG2.'_slowdown_flow_size.eps'

plot 'data/'.ARG1.'_'.ARG2.'_slowdown_size.dat' using 2:3:xtic(1) title 'pFabric' fillstyle pattern 1, \
	'' using 4:5 title 'Fastpass' fillstyle pattern 5 transparent lc rgb "#FF8000", \
	'' using 6:7 title 'pHost' fillstyle pattern 4, \
	'' using 8:9 title 'c-MP3' fillstyle pattern 6 transparent lc rgb "#009900", \
	'' using 10:11 title 'd-MP3' fillstyle pattern 2 transparent lc rgb "#003300"
