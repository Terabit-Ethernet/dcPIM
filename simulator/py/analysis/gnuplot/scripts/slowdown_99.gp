
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,9" linewidth 4 rounded fontscale 1.0

set xlabel ''
set ylabel '99% Slowdown' font ",9"

set key right top samplen 2 font ",9"
#unset key
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
# set tics out nomirror font ",9"


# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81

set border 3 back linestyle 80 


set xrange [-0.5:2.5]
set xtics 1
#set mxtics 1


set yrange [1:64]
#set ytics 2
set logscale y 2
#set ytics (1, 4, 16, 64, 256)
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 10 border
set output "img/".ARG1."_99_slowdown.eps"

plot "data/".ARG1."_99_slowdown.dat" using 2:xtic(1) title 'Homa Aeolus' fillstyle pattern 5 transparent lc rgb "#FF8000",\
	'' using 3 title 'NDP' fillstyle pattern 7 transparent lc rgb "#FF3333", \
	'' using 4 title 'HPCC' fillstyle pattern 4 transparent lc rgb "#5060D0", \
	'' using 5 title 'dcPIM' fillstyle pattern 2 transparent lc rgb "#00A000"
#	'' using 4 title 'pHost' fillstyle pattern 4, \
#        '' using 5 title 'dcPIM' fillstyle pattern 2 transparent lc rgb "#00A000"
#	'' using 5 title 'NDP' fillstyle pattern 7 transparent lc rgb "#FF3333", \
#        '' using 8 title 'DCTCP' fillstyle pattern 6 transparent lc rgb "#808080", \
#	'' using 6 title 'c-dcPIM' fillstyle pattern 6 transparent lc rgb "#009900", \
# 	'' using 7 title 'NDP' fillstyle pattern 7 transparent lc rgb "#FF3333"
