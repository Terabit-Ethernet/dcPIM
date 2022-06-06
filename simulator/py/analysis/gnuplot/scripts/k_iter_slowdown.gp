
# http://gnuplot.sourceforge.net/demo_5.0/histograms.html
set terminal eps font "Gill Sans,6" linewidth 4 rounded fontscale 1.0

set xlabel 'k' font ", 7"
set ylabel 'rounds' font ", 7"
set zlabel 'Slowdown' offset 5,6.5,-5.5 font ", 7"
set nokey
#set key right top samplen 2 font ",5"
#set key at -1.3,6 samplen 2 font ",6"
# set key below center horizontal noreverse enhanced autotitle box dashtype solid
#set tics out nomirror font ",9"


# Line style for axes
#set style line 80 lt rgb "#808080"

# Line style for grid
#set style line 81 lt 0  # dashed
#set style line 81 lt rgb "#808080"  # grey

#set grid back linestyle 81

#set border 3 back linestyle 80 

set xrange [0:6]
set yrange [0:6]
set zrange [0:5]
set autoscale
set dgrid3d 30,30
#set hidden3d
set ticslevel 0
set xtics 1
set ytics 1

#set style histogram clustered gap 1 title offset 4, -12
#set style data histograms

#set boxwidth 1.0 absolute
#set style fill   pattern 10 border

set output "img/".ARG1."_k_iter_slowdown.eps"

splot "data/".ARG1."_k_iter_slowdown.dat" using 1:($2-1):3 with lines