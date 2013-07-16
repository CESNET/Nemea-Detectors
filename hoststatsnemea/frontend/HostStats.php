<?php
/*
 * Frontend plugin: HostStats
 */

/* 
 * demoplugin_ParseInput is called prior to any output to the web browser 
 * and is intended for the plugin to parse possible form data. This 
 * function is called only, if this plugin is selected in the plugins tab. 
 * If required, this function may set any number of messages as a result 
 * of the argument parsing.
 * The return value is ignored.
 */
function HostStats_ParseInput( $plugin_id ) {

    $_SESSION['refresh'] = 0;
    //ob_start();
    //global $response;

    //$response = ob_get_contents();
    //ob_end_clean();

}


/*
 * This function is called after the header and the navigation bar have 
 * are sent to the browser. It's now up to this function what to display.
 * This function is called only, if this plugin is selected in the plugins tab
 * Its return value is ignored.
 */
function HostStats_Run( $plugin_id ) {
echo '
    <style>
        .shadetabs { width: 100%; }
        form { margin: 0; }
        .footer { display: none; }
    </style>

    <iframe id="pluginContent" src="plugins/HostStats/index.php" width="100%" height="85%" frameborder="0" ></iframe>

    <script type="text/javascript">
        /*
        @author Pixy
        */
        function winH() {
           if (window.innerHeight)
              /* NN4 a kompatibilni prohlizece */
              return window.innerHeight;
           else if
           (document.documentElement &&
           document.documentElement.clientHeight)
              /* MSIE6 v std. rezimu - Opera a Mozilla
              jiz uspely s window.innerHeight */
              return document.documentElement.clientHeight;
           else if
           (document.body && document.body.clientHeight)
              /* starsi MSIE + MSIE6 v quirk rezimu */
              return document.body.clientHeight;
           else
              return null;
        }

        window.onresize = function(event) {
            document.getElementById("pluginContent").style.height = winH()-105;
        }
        window.onresize();
    </script>
';

}

?>
