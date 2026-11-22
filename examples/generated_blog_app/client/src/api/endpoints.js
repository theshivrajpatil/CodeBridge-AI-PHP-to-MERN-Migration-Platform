import { http } from './http.js';

export const get_api_admin_stats = () => http("GET", `/admin/stats`);
export const delete_api_comments_by = (comment) => http("DELETE", `/comments/${comment}`);
export const get_api_health = () => http("GET", `/health`);
export const post_api_login = (body) => http("POST", `/login`, body);
export const post_api_logout = (body) => http("POST", `/logout`, body);
export const get_api_posts = () => http("GET", `/posts`);
export const post_api_posts = (body) => http("POST", `/posts`, body);
export const delete_api_posts_by = (post) => http("DELETE", `/posts/${post}`);
export const get_api_posts_by = (post) => http("GET", `/posts/${post}`);
export const patch_api_posts_by = (post, body) => http("PATCH", `/posts/${post}`, body);
export const put_api_posts_by = (post, body) => http("PUT", `/posts/${post}`, body);
export const get_api_posts_by_comments = (post) => http("GET", `/posts/${post}/comments`);
export const post_api_register = (body) => http("POST", `/register`, body);
