
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,9" linewidth 4 rounded fontscale 1.0

set xlabel ''
set ylabel 'Utilization' font ",9"

set grid y
set key left bottom opaque samplen 2 font ",9"
#set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror
set tics font ",9"
set border 3 front linetype black linewidth 2.0 dashtype solid

set xrange [-0.5:2.5]
set xtics 1
#set mxtics 1

set yrange [0:1]
# set ytics 5

set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 4

set style histogram clustered gap 1 title offset character 0, 0, 0
set style data histograms

set boxwidth 1.0 absolute
set style fill   pattern 7 border

set output "img/fat_tree_util.eps"
plot 'data/fat_tree_util.dat' using 5 title 'dcPIM' fillstyle pattern 2 transparent lc rgb "#00A000"
