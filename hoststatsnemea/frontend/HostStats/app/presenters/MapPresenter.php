<?php

/**
 * IP Map presenter.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class MapPresenter extends BasePresenter
{

    /** @persistent */
    public $timeslot;

    /** @persistent */
    public $min = 0;

    /** @persistent */
    public $max = 100;

    /** @persistent */
    public $zoom = 1;

    /** @persistent */
    public $col = 'flows';

    /** @persistent */
    public $outofrangeView = true;

    /** @persistent */
    public $prefixLength = 16;

    /** @persistent */
    public $baseAddress = '0.0.0.0';

    /** @persistent */
    public $basePrefixLength = 0;

    const IN = 'in';
    const OUT = 'out';
    const DIFF = 'diff';


    protected $gradient = array();

    public function startup() {
        parent::startup();

        $width = $this->zoom*256;
        $this->gradient = array_merge($this->gradient,self::gradient(Image::rgb(0,0,255),Image::rgb(0,255,255),(int)$width/4));
        array_pop($this->gradient); // odeberem posledni protoze je hnd v dalsim

        $this->gradient = array_merge($this->gradient,self::gradient(Image::rgb(0,255,255),Image::rgb(0,255,0),(int)$width/4));
        array_pop($this->gradient); // odeberem posledni protoze je hnd v dalsim

        $this->gradient = array_merge($this->gradient,self::gradient(Image::rgb(0,255,0),Image::rgb(255,255,0),(int)$width/4));
        array_pop($this->gradient); // odeberem posledni protoze je hnd v dalsim

        $this->gradient = array_merge($this->gradient,self::gradient(Image::rgb(255,255,0),Image::rgb(255,0,0),(int)$width/4));
        array_pop($this->gradient); // odeberem posledni protoze je hnd v dalsim
    }

    /**
     * prepare Default view
     * @param null|string $timeslot
     */
    public function renderDefault($timeslot = null)
	{
        if($timeslot)
            $timeslot = new Timeslot($timeslot);
        try {
            if(!$timeslot)
                $timeslot = $this->model->getStatus()->timeslot;
        } catch (HSCException $e) {}
        if(!$timeslot)
            $timeslot = new Timeslot(); // Aktualni

        $this->template->timeslot = $timeslot;
        $this->template->col = $this->col;
        $this->template->zoom = $this->zoom;
        $this->template->base = Nettools::getIp4Prefix($this->baseAddress, $this->basePrefixLength);
        $this->template->baseLength = $this->basePrefixLength;

        // set default value to form
        $this['frmTimestamp']['timeslot']->setDefaultValue( $timeslot->format( $this->formats->timeslot ) );


        if($this->isAjax)
            $this->invalidateControl();
	}


     /**
     * Create timestamp form
     * @return AppForm
     */
    public function createComponentFrmTimestamp() {
        $frm = new AppForm();
        $frm->addText('timeslot','Timeslot')
            ->setDefaultValue($this->timeslot);
        $frm->addSubmit('send','Submit');
        $frm->onSuccess[] = array($this,'frmTimestampSuccess');
        return $frm;
    }

    /**
     * Callback on success timestamp form
     * @param Form $frm
     */
    public function frmTimestampSuccess(Form $frm) {
        $this->timeslot = $frm->values->timeslot;

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }


    /**
     * Generate IP map image
     * @param name of timeslot
     * @param data colum
     * @param size of one "pixel"
     * @param number bytes = prefix length
     */
    public function actionIPmap($timeslot, $col, $type = self::IN) {

        $cache = new Cache($this->context->cacheStorage, 'ipmaps');
        $cacheKey = array($this->timeslot,$this->max,$this->min,$this->zoom,$this->prefixLength);

        /*
        if($image = $cache->load($cacheKey)) {
            $image = Image::fromString($image);
            $image->send();
            $this->terminate();
        }
        */

        $timeslot = new Timeslot($timeslot);
        try {
            $data = $this->model->getTimeslotIpMap($timeslot, $this->profile, $this->baseAddress, $this->basePrefixLength);
        } catch(HSCException $e) {
            $data = array();
        }



        $size = pow(2,$this->prefixLength);
        $side = sqrt($size);
        $image = Image::fromBlank(sqrt($size) * $this->zoom, sqrt($size) * $this->zoom, Image::rgb(0, 0, 0)); // black square

        foreach($data as $row) {

            if(!isset($row["in_{$col}"]) || !isset($row["out_{$col}"]))
                break;

            $prefix = Nettools::getIp4Prefix($row['prefix'], $this->prefixLength, $this->basePrefixLength);

            //$x = ($prefix % $side);
            //$y = floor($prefix / $side);
            self::d2xy($side, $prefix, $x, $y);


            //$row = array('out_flows' => (int) 0, 'in_flows' => 20);

            // zjistime barvu z gradientu
            if($type == self::IN) {
                $intenzity = $row["in_{$col}"];
            } elseif($type == self::OUT) {
                $intenzity = $row["out_{$col}"];
            } elseif($type == self::DIFF) {
                $intenzity = array($row["in_{$col}"], $row["out_{$col}"]);
            } else {
                break;
            }


            if($type == self::DIFF) {
                list($in, $out) = $intenzity;

                if(!$this->outofrangeView) {
                    if($in > $this->max || $out > $this->max)
                        continue;
                }

                // intenzita od -max do +max
                $in = min($this->max, $in);
                $out = min($this->max, $out);


                //   out | ------- 0 ------- | in
                //  -max | ------- 0 ------- | +max
                //     0 | ------ max ------ | 2max

                //dump($in,$out);

                $intenzity = $this->max - $out + $in;
                $inx = floor( (($intenzity) / ($this->max+$this->max))*(count($this->gradient)-1));

            } else {
                if(!$this->outofrangeView) {
                    if($intenzity < $this->min || $intenzity > $this->max)
                        continue;
                }

                $intenzity = min($this->max,$intenzity); // Pokud je vetsi nez max, vezmeme max
                $intenzity = max($this->min,$intenzity); // Pokud je mensi nez min, vezmeme min

                $inx = floor((($intenzity-$this->min) / ($this->max-$this->min))*(count($this->gradient)-1));
            }


            $color = $this->gradient[$inx];
            $image->filledRectangle($x * $this->zoom, $y * $this->zoom, ($x * $this->zoom)+$this->zoom, ($y * $this->zoom)+$this->zoom, $color);
        }


        $cache->save( $cacheKey, (string) $image);

        $image->send();
        $this->terminate();
    }


    public function actionIPmapRange() {
        $height = 20;
        $width = count($this->gradient);
        $image = Image::fromBlank($width, $height, Image::rgb(0, 0, 0)); // black square

        for($x = 0; $x < $width; $x++) {
            for($y = 0; $y < $height; $y++) {
                $color = $this->gradient[$x]; //Image::rgb($prefix % 255,$prefix %  255,$prefix %  255);
                $image->setPixel($x,$y, $color);
            }
        }

        $image->string(5, 5, 2, "{$this->min}", Image::rgb(255,255,255));
        $image->string(5, $width -(strlen($this->max)*9 + 5), 2, "{$this->max}", Image::rgb(255,255,255));

        $image->send();
        $this->terminate();
    }
    public function actionIPmapRangeDiff() {
        $height = 20;
        $width = count($this->gradient);
        $image = Image::fromBlank($width, $height, Image::rgb(0, 0, 0)); // black square

        for($x = 0; $x < $width; $x++) {
            for($y = 0; $y < $height; $y++) {
                $color = $this->gradient[$x]; //Image::rgb($prefix % 255,$prefix %  255,$prefix %  255);
                $image->setPixel($x,$y, $color);
            }
        }

        $image->string(5, 5, 2, "{$this->max} Out", Image::rgb(255,255,255));
        $image->string(5, $width -(strlen("$this->max In")*9 + 5), 2, "{$this->max} In", Image::rgb(255,255,255));
        $image->string(5, floor(($width / 2) - (strlen("In = Out")*9 / 2)) , 2, "In = Out", Image::rgb(255,255,255));

        $image->send();
        $this->terminate();
    }


    public function createComponentFrmConfigure() {
        $frm = new AppForm();
        $frm->setRenderer(new MyFormRenderer);
        $frm->getElementPrototype()->class('ajax');

        $frm->addSelect('col',"Intensity of", array(
                    'flows' => 'flows',
                    'packets' => 'packets',
                    'bytes' => 'bytes',
                ))->setDefaultValue($this->col);
        $frm->addText('max',"Range max")
            ->setDefaultValue($this->max)
            ->addRule(Form::INTEGER)
            ->addRule(Form::RANGE,"%label must in range 0,max",0,null);
        $frm->addText('min',"Range min")
            ->setDefaultValue($this->min)
            ->addRule(Form::INTEGER)
            ->addRule(Form::RANGE,"%label must in range 0,max",0,$frm['max']);
        $frm->addCheckbox("outofrange_view","View out of range")
            ->setDefaultValue($this->outofrangeView);

        $frm->addText('base',"Specific subnet")
            ->setDefaultValue(sprintf("%s/%s", $this->baseAddress, $this->basePrefixLength));

        $frm->addSubmit('send',"Refresh");


        $frm->onSuccess[] = callback($this, 'frmConfigureSuccess');
        return $frm;
    }


    public function frmConfigureSuccess(Form $frm) {
        $this->min = $frm->values->min;
        $this->max = $frm->values->max;
        $this->col = $frm->values->col;
        $this->outofrangeView = $frm->values->outofrange_view;

        $base = explode("/",$frm->values->base);
        if(isset($base[0]) && Nettools::isIPv4(trim($base[0])))
            $this->baseAddress = trim($base[0]);
        else
            $frm['base']->addError("Base prefix is not valid IPv4 address");

        if(isset($base[1]) && trim($base[1]) <= 16 )
            $this->basePrefixLength = (int) trim($base[1]);
        else
            $frm['base']->addError("Base prefix length is not valid. Must be a whole number to /16");


        if($frm->hasErrors()) {
            $this->invalidateControl();
            return;
        }

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }


    protected static function gradient($from, $to, $steps) {

        $step['r'] = ($from['red'] - $to['red']) / ($steps - 1);
        $step['g'] = ($from['green'] - $to['green']) / ($steps - 1);
        $step['b'] = ($from['blue'] - $to['blue']) / ($steps - 1);

        $colors = array();
        for($i = 0; $i <= $steps; $i++) {
            $r = floor($from['red'] - ($step['r'] * $i));
            $g = floor($from['green'] - ($step['g'] * $i));
            $b = floor($from['blue'] - ($step['b'] * $i));
            $color = Image::rgb($r,$g,$b);

            //$hex = sprintf("%02x%02x%02x",$color['red'],$color['green'],$color['blue']);
            $colors[] = $color;
        }
        return $colors;
    }

    //convert (x,y) to d
    protected static function xy2d($n, $x, $y) {
        $rx = $ry = $s = $d = 0;
        for ($s=$n/2; $s>0; $s/=2) {
            $rx = ($x & $s) > 0;
            $ry = ($y & $s) > 0;
            $d += $s * $s * ((3 * $rx) ^ $ry);
            self::rot($s, $x, $y, $rx, $ry);
        }
        return $d;
    }

    //convert d to (x,y)
    protected static function d2xy($n, $d, &$x, &$y) {
        $rx = 0;
        $ry = 0;
        $s = 0;
        $t = $d;
        $x = $y = 0;
        for ($s=1; $s<$n; $s*=2) {
            $rx = 1 & ($t/2);
            $ry = 1 & ($t ^ $rx);
            self::rot($s, $x, $y, $rx, $ry);
            $x += $s * $rx;
            $y += $s * $ry;
            $t /= 4;
        }
    }

    //rotate/flip a quadrant appropriately
    protected static function rot($n, &$x, &$y, $rx, $ry) {
        if ($ry == 0) {
            if ($rx == 1) {
                $x = $n-1 - $x;
                $y = $n-1 - $y;
            }
            //Swap x and y
            $t  = $x;
            $x = $y;
            $y = $t;
        }
    }
}
