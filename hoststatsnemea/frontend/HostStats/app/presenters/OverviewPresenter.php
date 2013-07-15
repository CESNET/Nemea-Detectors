<?php

/**
 * Overview presenter.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class OverviewPresenter extends BasePresenter
{

    /**
     * Prepare Default view
     */
    public function renderDefault()
	{

        $server = ArrayHash::from($this->context->parameters['hoststats']);
        try {

            $status = $this->model->getStatus();

            $from = $status->timeslot ? $status->timeslot->getModify('- 12 hours') : null;
            $to = $status->timeslot ? $status->timeslot : null;

            $history = $this->model->getFlowCntHistory(HSConnection::ALL, $to, $to);
            $status->flows = current($history);
            $history = $this->model->getHostCntHistory(HSConnection::ALL, $to, $to);
            $status->hosts = current($history);

            $this->template->status = $status;

            // Graf aktivních flows
            $color = array('all'=>'#008DFF','ssh'=>'#7070D0','telnet'=>'#FA5833','dns'=>'#F8FF00');
            foreach($this->profiles as $profile=>$profileName) {
                //if($profile!='all')
                    $flowCntHistory[] = array(
                        'label' => $profile,
                        'color' => isset($color[$profile]) ?  $color[$profile] : null,
                        'data' => $this->model->getFlowCntHistory($profile, $from, $to),
                    );
            }

            $this->template->chartHistoryFlows = Json::encode( $flowCntHistory );
            $this->payload->chartHistoryFlows = $flowCntHistory; // kvuli ajax refreshi

            // Graf aktivních hostů
            //$color = array('ssh'=>'#008DFF','telnet'=>'#AFD8F8','dns'=>'#06FBFF');
            foreach($this->profiles as $profile=>$profileName) {
                //if($profile!='all')
                    $hostCntHistory[] = array(
                        'label' => $profile,
                        'color' => isset($color[$profile]) ?  $color[$profile] : null,
                        'data' => $this->model->getHostCntHistory($profile, $from, $to)
                    );
            }


            $this->template->chartHistoryHosts = Json::encode($hostCntHistory);
            $this->payload->chartHistoryHosts = $hostCntHistory; // kvuli ajax refreshi



            if(!$this->isAjax()) {
                // Poslední detekce utoku
                $this->template->lastDetections = $this->model->getDetectionLogList("desc",10);
            }

            $server->status = true;
        } catch(HSCException $e) {
            $this->flashMessage($e->getMessage(), 'error');
            $server->status = false;
        }

        $this->template->server = $server;

    }

    /**
     * Do signal refresh!
     */
    public function handleRefresh() {
        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }



}
