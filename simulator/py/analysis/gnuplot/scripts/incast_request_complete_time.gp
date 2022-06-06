set terminal eps font "Gill Sans,7" linewidth 4 rounded fontscale 1.0

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

#set style line 1 lt rgb "#A00000" lw 2 pt 1
#set style line 2 lt rgb "#00A000" lw 2 pt 6
#set style line 3 lt rgb "#5060D0" lw 2 pt 2
#set style line 4 lt rgb "#F25900" lw 2 pt 9
#set style line 5 lt rgb "#CC0066" lw 2 pt 7
#set style line 6 lt rgb "#00A000" lw 2 pt 7

#set style line 1 lt rgb "#A00000"
#set style line 2 lt rgb "#00A000"
#set style line 3 lt rgb "#5060D0"
#set style line 4 lt rgb "#F25900"
#set style line 5 lt rgb "#CC0066"
#set style line 6 lt rgb "#00A000"

set xlabel 'Number of Senders'
set ylabel 'Total Request Completion Time(ms)'

set key bottom right

set xrange [5:50]
set xtics 5,5,50

set yrange [0: 10]

set output "img/incast_request_complete_time.eps"


plot "data/incast_request_complete_time.dat" using 1:2:3 with lp ls 1 title 'pFabric',\
'' using 1:4:5 with lp ls 6 title 'dcPIM'
#'' using 1:4:5 with lp ls 4 title 'Fastpass',\
#'' using 1:6:7 with lp ls 3 title 'pHost',\
#'' using 1:10:11 with lp ls 6 title 'dcPIM'
#'' using 1:10:11 with lp ls 2 title 'c-dcPIM',\
#'' using 1:12:13  with lp ls 5 title 'NDP' ,\


# set terminal xterm
# replot
