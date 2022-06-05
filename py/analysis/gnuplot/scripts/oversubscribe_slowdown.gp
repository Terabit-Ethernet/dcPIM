
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,9" linewidth 4 rounded fontscale 1.0

set xlabel ''
set ylabel 'Mean Slowdown' font ",9"
set size 1, 1

#set key at -1.1,3 samplen 2 font ",7"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
#set tics out nomirror font ",9"
#set key right middle opaque samplen 2 font ",6"

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
set lmargin at screen 0.35
set rmargin at screen 1.2
set bmargin at screen 0.15
set tmargin at screen 0.9
set yrange [1:8]
set ytics 1
#set logscale y 2
#set ytics (0.25, 0.5, 1, 2, 4, 8, 16, 32)
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 10 border

set output "img/".ARG1."_slowdown.eps"

plot "data/".ARG1."_slowdown.dat" using 2:xtic(1) title 'NDP' fillstyle pattern 7 transparent lc rgb "#FF3333", \
	'' using 3 title 'HPCC' fillstyle pattern 4 transparent lc rgb "#5060D0", \
	'' using 4 title 'dcPIM' fillstyle pattern 2 transparent lc rgb "#00A000"
#	'' using 3 title 'Fastpass' fillstyle pattern 5 transparent lc rgb "#FF8000", \
#	'' using 4 title 'pHost' fillstyle pattern 4, \
#	'' using 6 title 'dcPIM' fillstyle pattern 2 transparent lc rgb "#00A000"
# 	'' using 7 title 'Homa' fillstyle pattern 3 transparent lc rgb "#FF3333"
#       '' using 5 title 'c-dcPIM' fillstyle pattern 6 transparent lc rgb "#009900", \
