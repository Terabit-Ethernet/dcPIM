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
set xtics 0.1
#set log y 

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

set xlabel 'Load'
set ylabel 'Utilization'

set key bottom right

set xrange [0.5:0.8]
set xtics 0.5,0.1,0.8
set yrange [0.7:1]

set output "img/".ARG1."_bursty_load_util.eps"

plot "data/".ARG1."_bursty_load_util.dat" using 1:2 with lp ls 8 title 'Homa Aeolus',\
   '' using 1:3 with lp ls 7 title 'NDP',\
   '' using 1:4 with lp ls 3 title 'HPCC',\
   ''  using 1:5 with lp ls 6 title 'dcPIM'
#   '' using 1:3 with lp ls 7 title 'NDP',\
#'' using 1:3 with lp ls 8 title 'Homa Limit',\
#'' using 1:4 with lp ls 7 title 'Homa Unlimit'
#'' using 1:3 with lp ls 4 title 'Fastpass',\
#'' using 1:4 with lp ls 3 title 'pHost',\
#'' using 1:5 with lp ls 5 title 'NDP',\
#'' using 1:8 with lp ls 7 title 'dcPIM',\
#'' using 1:6 with lp ls 2 title 'c-dcPIM',\
# set terminal xterm
# replot
