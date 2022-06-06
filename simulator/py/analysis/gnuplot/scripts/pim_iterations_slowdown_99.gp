set terminal eps font "Gill Sans,9" linewidth 4 rounded fontscale 1.0

# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
             # borders are useless and make it harder
             # to see plotted lines near the border.
    # Also, put it in grey; no need for so much emphasis on a border.


#set log x
#set mxtics 10    # Makes logscale look good.

# Line styles: try to pick pleasing colors, rather
# than strictly primary colors or hard-to-see colors
# like gnuplot's default yellow.  Make the lines thick
# so they're easy to see in small plots in papers.
set style line 1 lt rgb "#A00000" lw 2 pt 1
set style line 2 lt rgb "#00A000" lw 2 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9
set style line 5 lt rgb "#CC0066" lw 2 pt 7
set style line 6 lt rgb "#00A000" lw 2 pt 3
set style line 7 lt rgb "#FF3333" lw 2 pt 6
set style line 8 lt rgb "#FF8000" lw 2 pt 2

set xlabel 'Rounds'
set ylabel '99% Slowdown'

set key bottom right

set xrange [1:5]
set xtic(1,2,3,4,5)
set yrange [0:15]

set output "img/pim_k_slowdown_99.eps"

plot "data/pim_k_slowdown_99.dat" using 1:2 with lp ls 1 title 'k=1',\
'' using 1:3 with lp ls 3 title 'k=2',\
'' using 1:4 with lp ls 6 title 'k=4',\
'' using 1:5 with lp ls 7 title 'k=8'

# set terminal xterm
# replot
