<?php
/**
 * Capabilities.php, where we manage user permissions and access controls
 **/
namespace CFPB\Utils\Capabilities;

class Custom_Caps
{
    // Add our filters
    public function filter_roles()
    {
        add_filter( 'editable_roles', array( $this, 'editable_roles' ) );
        add_filter( 'map_meta_cap', array( $this, 'map_meta_cap' ), 10, 4 );
        add_filter( 'ramp-user-access-base', array( $this, 'ramp_user_access_filter' ) );
    }

    /**
     * Prevent access to RAMP.
     *
     * Extension point: filters the base capability required for RAMP access.
     **/
    public function ramp_user_access_filter( $level )
    {
        return 'publish_pages';
    }

    // Remove 'Administrator' from the list of roles if the current user is not an admin.
    public function editable_roles( $roles )
    {
        if ( isset( $roles['administrator'] ) && ! current_user_can( 'manage_options' ) ) {
            unset( $roles['administrator'] );
        }
        return $roles;
    }

    /**
     * Map primitive capabilities to meta capabilities.
     *
     * Like the builtin map_meta_cap, this accepts four args and allows filtering of capabilities out of
     * less privileged users. In this case, we're modifying the ability to delete and modify
     * administrators, restricting it to only admins.
     *
     * @param array $caps    An array of all available capabilities.
     * @param string $cap    Name of the meta capability to map to.
     * @param int $user_id   The current or specified user ID.
     * @param array $args    An array of extra arguments for the capability.
     *
     * @return array An array of capabilities, should be hooked into map_meta_cap.
     *
     * @see WordPress' map_meta_cap filter.
     **/
    public function map_meta_cap( $caps, $cap, $user_id, $args )
    {
        if ( 'promote_user' === $cap && ! current_user_can( 'manage_options' ) ) {
            $caps[] = 'do_not_allow';
        } elseif ( 'delete_users' === $cap && ! current_user_can( 'manage_options' ) ) {
            $caps[] = 'do_not_allow';
        }

        return $caps;
    }
}

$Custom_caps = new Custom_Caps();
$Custom_caps->filter_roles();
?>
