 $(document).ready(function() {
	

	$('ul.main-menu li a').each(function(){
		if($($(this))[0].href==String(window.location))
			$(this).parent().addClass('active');
	});


     $('.ipmap').livequery(function(){

         var zoom = parseInt($(this).data('zoom')) ? parseInt($(this).data('zoom')) : 1 ;
         var base = parseInt($(this).data('base')) ? parseInt($(this).data('base')) : 0 ;
         var baseLength = parseInt($(this).data('base-length')) ? parseInt($(this).data('base-length')) : 0 ;

         var $img = $(this).children('img');

         var long2ip = function (ip) {
             if (!isFinite(ip))
                 return false;
             return [ip >>> 24, ip >>> 16 & 0xFF, ip >>> 8 & 0xFF, ip & 0xFF].join('.');
         }

         var $tipsy = $('<div></div>').css({
             position: 'absolute',
             backgroundColor: 'rgba(255,255,255,0.9)',
             color: 'black',
             zIndex: 100,
             whiteSpace: 'nowrap'
         });
         $tipsy.hide().appendTo( $(this).css({position: 'relative'}) );
         $img.mousemove(function(e){
             var offset = $(this).offset();
             var x = Math.round( (e.pageX - offset.left) / zoom ) ;
             var y = Math.round( (e.pageY - offset.top) / zoom ) ;
             var w = Math.round($(this).width() / zoom);
             var h = Math.round($(this).height() / zoom);
             var prefixLength = (Math.log(w*h))/(Math.log(2)) ; // log[a][x]

            //var prefix = x + (y * w);
            var prefix = xy2d(256,x,y);
            prefix = (base << prefixLength) + prefix;

            var min = ((prefix) << (32-prefixLength-baseLength)); // doplnen 0 do 32bitu
            var max = ((prefix) << (32-prefixLength-baseLength)) + (Math.pow(2, 32-prefixLength-baseLength)-1); // doplnen 1 do 32bitu

             $tipsy.html(long2ip(min) + " - " + long2ip(max)).css({top: (y*zoom)+20, left: (x*zoom)+20}).show();
         }).mouseleave(function(){
            $tipsy.hide();
         });

     });

     $('ipmap_max').livequery(function() {
         $(this).spinner();
     });

     $('#frm-frmProfile').livequery(function(){
         var $_this = $(this);
         $(this).find('select[name=profile]').change(function() {$_this.submit();});
         $(this).find('input[name=send]').hide();
     });

     $('#frm-frmLimit').livequery(function(){
         var $_this = $(this);
         $(this).find('[name=limit]').change(function() {$_this.submit();});
     });


     $("a.ajax").live("click", function (e) {
         e.preventDefault();
         $.get(this.href);
     });

     $('form.ajax').live('submit',function(){
         $(this).ajaxSubmit();
         return false;
     });

     $('[data-ajaxload]').livequery(function(){
         var $spinner = $('<div></div>').attr('id','ajax-spinner-inner-block').appendTo( $(this) );
         var $_this = $(this);
         $.ajax({
            url: $_this.data('ajaxload'),
            global: false,
            success: function() {},
            dataType: 'text'
         }).done(function(html) {
             $_this.fadeOut('slow',function(){
                 $_this.html(html).fadeIn('slow');
             });
         });
     });

     $('#refresh-overview').livequery(function(){
        var interval = $(this).data('interval') * 1000; //1000 * 60; // ms
        var link = $(this).data('refresh');
        setInterval(function() {

            $.ajax({
                url: link,
                global: false,
                dataType: 'json',
                success: function() {} // aby to nevzalo nette.success
            })
            .done(function(payload) {

                for(id in payload.snippets) {
                    $('#' + id).html( payload.snippets[id] );
                }
                var $plot;
                if( $plot = $("#chartHistoryHosts").data('plot') ) {
                    var data = json2namedChartData( payload.chartHistoryHosts );
                    $plot.setData( data );
                    $plot.draw();
                }
                if( $plot = $("#chartHistoryFlows").data('plot') ) {
                    var data = json2namedChartData( payload.chartHistoryFlows );
                    $plot.setData( data );
                    $plot.draw();
                }
            });

        }, interval);
     });

    $('#ipaddress,#filter').live("change",function(){
        $(this).parents('form').submit();
    });
    $('#timewindow,#timeslot').livequery(function(){
        var $_this = $(this);
        var $panel = $(this).find('.panel');
        var $prevnext = $(this).find('.prev,.next');

        $(this).click(function(e) {
            e.stopPropagation();
            if(!$(this).hasClass('focus'))
                $(this).addClass('focus');
            $panel.width( $(this).width()-2 ).hide();
            $panel.slideDown();
        });

        $panel.click(function(e){
            e.stopPropagation();
        });

        $panel.children('a').click(function(e){
            $.get(this.href);
            $panel.slideUp(function() { $_this.removeClass('focus'); });
            return false;
        })
        $panel.children('.pickers').find('.btn').click(function(e){
            e.stopPropagation();
            //var $from = $panel.children('.pickers').find('.from');
            //var $to = $panel.children('.pickers').find('.to');
            $(this).parents('form').submit();
            $panel.slideUp(function() { $_this.removeClass('focus'); });
            return false;
        });
        $prevnext.click(function(e){
            e.preventDefault();
            e.stopPropagation();
            $.get(this.href);
        });

    });
    $(document).click(function(){
         $('#timewindow, #timeslot').each(function(){
             var $_this = $(this);
             $_this.find('.panel').slideUp(function() { $_this.removeClass('focus'); });
         });
     });


     /* ---------- Datapicker ---------- */
     $('.datepicker').livequery(function(){
         $(this).datepicker({
             dateFormat: "dd.mm.yy",
             maxDate: new Date()
         });
         $('.ui-datepicker').click(function(e){
             e.stopPropagation();
         });
     });

     $('.datetimepicker').livequery(function(){
        $(this).datetimepicker({
             timeFormat: 'HH:mm',
             dateFormat: "dd.mm.yy",
             stepMinute: 5,
             maxDate: new Date()
         });
         $('.ui-datepicker').click(function(e){
             e.stopPropagation();
         });
     });


    $('tr.link').livequery(function(){
        $(this).css('cursor','pointer').click(function(){
            var href = $(this).find('a:first').attr('href');
            location.href = href;
        });
    });


     /* Zapamatovavaci input */
     $(".rememberme").each(function(){
         if(!this.name)
             return;

         var val = $.cookie(this.name);

         if($(this).is(":checkbox")) {
             val = val == "true" || val == true  ? true : false;
             this.checked = val;

             $(this).change(function() {
                 $.cookie(this.name, $(this).is(":checked"), {expires: 7});
             });
         } else {
             if(val != null)
                 $(this).val(val);
             $(this).change(function() {
                 $.cookie(this.name, $(this).val(), {expires: 7});
             });
         }
     });

     /* ---------- Uniform ---------- */

     $("input:checkbox, input:radio, input:file").not('[data-no-uniform="true"],#uniform-is-ajax').livequery(function(){
         $(this).uniform();
     })

     /* ---------- Choosen ---------- */
     $('[data-rel="chosen"],[rel="chosen"]').livequery(function(){
        $(this).chosen();
     })

     /* ---------- Tabs ---------- */
     $('#myTab a:first').tab('show');
     $('#myTab a').click(function (e) {
         e.preventDefault();
         $(this).tab('show');
     });

     /* ---------- Makes elements soratble, elements that sort need to have id attribute to save the result ---------- */
     $('.sortable').sortable({
         revert:true,
         cancel:'.btn,.box-content,.nav-header',
         update:function(event,ui){
             //line below gives the ids of elements, you can make ajax call here to save it to the database
         }
     });

     /* ---------- Tooltip ---------- */
     $('[rel="tooltip"],[data-rel="tooltip"]').tooltip({"placement":"bottom",delay: { show: 400, hide: 200 }});

     /* ---------- Popover ---------- */
     $('[rel="popover"],[data-rel="popover"]').popover();


     $('.btn-close').click(function(e){
         e.preventDefault();
         $(this).parent().parent().parent().fadeOut();
     });
     $('.btn-minimize').click(function(e){
         e.preventDefault();
         var $target = $(this).parent().parent().next('.box-content');
         if($target.is(':visible')) $('i',$(this)).removeClass('icon-chevron-up').addClass('icon-chevron-down');
         else 					   $('i',$(this)).removeClass('icon-chevron-down').addClass('icon-chevron-up');
         $target.slideToggle();
     });
     $('.btn-setting').click(function(e){
         e.preventDefault();
         $('#myModal').modal('show');
     });



     $("#chartHistoryHosts").each(function() {
        var data = json2namedChartData( $(this).data('chart') );

        var options = {
            series: { shadowSize: 1 },
            lines: { fill: true, fillColor: { colors: [ { opacity: 0.6 }, { opacity: 0.1 } ] }},
            yaxis: { min: 0 },
            xaxis:{ mode:"time", timeformat: '%y/%0m/%0d %H:%M' },
           // colors: ["#F4A506"],
            grid: {
                tickColor: "#dddddd",
                borderColor: "#dddddd",
                borderWidth: 1
            }
        };

        $(this).data( 'plot', $.plot($(this), data, options) );
    });

    $("#chartHistoryFlows").each(function() {
        var data = json2namedChartData( $(this).data('chart') );

        var options = {
            series: { shadowSize: 1 },
            lines: { fill: true, fillColor: { colors: [ { opacity: 0.6 }, { opacity: 0.1 } ] }},
            yaxis: { min: 0 },
            xaxis:{ mode:"time", timeformat: '%y/%0m/%0d %H:%M' },
            //colors: ["#FA5833"],
            grid: {
                tickColor: "#dddddd",
                borderColor: "#dddddd",
                borderWidth: 1
            },
        };

        /*
        $(this).bind("plotclick", function (event, pos, item) {
            console.log(event, pos, item);
        });
        */
        $(this).data( 'plot', $.plot($(this), data, options) );

    });

    $("#chartHistoryIp").livequery(function() {
        var $chart = $(this);


        var data = json2chartDataCol( $(this).data('chart'), 'in_flows' );

        //var data = [];
        var options = {
            series: { shadowSize: 1 },
            lines: { fill: true, fillColor: { colors: [ { opacity: 0.6 }, { opacity: 0.1 } ] }},
            yaxis: { min: 0 },
            xaxis:{ mode:"time", timeformat: '%y-%0m-%0d %H:%M', min: data[0][0], max: data[data.length-1][0] },
            colors: ["#2FABE9","#12F5E9"],
            grid: {
                tickColor: "#dddddd",
                borderWidth: 0
            },
            selection: {
                mode: "x",
                color: "red"
            }
        };

        var chart = $.plot($(this), data, options);

        function refreshChart() {
            var data = [];
            $("#chartHistoryIpSelect input:checkbox").each(function(){
                if($(this).is(':checked')) {
                    data.push({
                        label: $(this).parents('label.checkbox').text(),
                        data: json2chartDataCol( $chart.data('chart'), this.name ),
                        color: $(this).data('color'),
                    })
                }
            });
            if(data.length==0)
                data=[[]];

            chart.setData(data);
            chart.setupGrid();
            chart.draw();
        }

        $("#chartHistoryIpSelect input:checkbox").change(refreshChart);
        if($("#chartHistoryIpSelect input:checkbox:checked").length==0)
            $("#chartHistoryIpSelect input:checkbox:first").attr('checked','checked').uniform('refresh');

        refreshChart();
    });

});


function json2chartDataCol( data, col ) {
    var array = [];
    $.each(data, function(key,val){
        array.push([ key*1000, val[col] ]);
    });
    return array;
}
function json2chartData( data ) {

    var array = [];
    $.each(data, function(key,val){
        array.push([key*1000, val])
    });
    return array;
}

 function json2namedChartData( list ) {

     for(i in list) {
         var data = [];
         $.each(list[i].data, function(key,val){
             data.push([key*1000, val])
         });
         list[i].data = data;
     }
     return list;
 }


 //convert (x,y) to d
 function xy2d (n, x, y) {
     var rx, ry, s, d=0;
     for (s=n/2; s>0; s/=2) {
         rx = (x & s) > 0;
         ry = (y & s) > 0;
         d += s * s * ((3 * rx) ^ ry);

         var res = rot(s, x, y, rx, ry);
         x = res.x;
         y = res.y;
     }
     return d;
 }

 //convert d to (x,y)
 function d2xy(n, d) {
     var rx=d, ry=d, s=d, t = d;
     var x = y = 0;
     for (s=1; s<n; s*=2) {
         rx = 1 & (t/2);
         ry = 1 & (t ^ rx);

         var res = rot(s, x, y, rx, ry);
         x = res.x;
         y = res.y;

         x += s * rx;
         y += s * ry;
         t /= 4;
     }
     return {x: x, y: y};
 }

 //rotate/flip a quadrant appropriately
 function rot(n, x, y, rx, ry) {
     if (ry == 0) {
         if (rx == 1) {
             x = n-1 - x;
             y = n-1 - y;
         }

         //Swap x and y
         var t  = x;
         x = y;
         y = t;
     }
     return {x: x, y: y};
 }

