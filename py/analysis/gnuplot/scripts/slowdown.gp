
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html

set xlabel ''
set ylabel 'Mean Slowdown' font ",18"
set size 1, 1
set grid y
set key at -1.1,3 samplen 2 font ",16"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror font ",18"
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [-0.5:2.5]
set xtics 1
#set mxtics 1
set lmargin at screen 0.35
set rmargin at screen 1.2
set bmargin at screen 0.15
set tmargin at screen 0.9
set yrange [0:32]
# set ytics 5
set logscale y 2
set ytics (0.25, 0.5, 1, 2, 4, 8, 16, 32)
set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 2

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 10 border

set terminal eps enhanced
set output "img/".ARG1."_slowdown.eps"

plot "data/".ARG1."_slowdown.dat" using 2:xtic(1) title 'pFabric' fillstyle pattern 1, \
	'' using 3 title 'Fastpass' fillstyle pattern 5 transparent lc rgb "#FF8000", \
	'' using 4 title 'pHost' fillstyle pattern 4, \
	'' using 6 title 'NDP' fillstyle pattern 7 transparent lc rgb "#A52A2A", \
	'' using 5 title 'RUF' fillstyle pattern 2 transparent lc rgb "#009900"
